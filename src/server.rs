// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use rustls::{ServerConfig, server::VerifierBuilderError};
use thiserror::Error;
use tokio::time::sleep;
use tokio_stream::{Stream, StreamExt};

#[cfg(feature = "tracing")]
use tracing::{debug, error, info};

/// Errors that can occur while building or consuming a server-config stream.
///
/// These represent failures either from the user-provided stream/builder
/// or from [`rustls`] itself.
#[derive(Debug, Error)]
pub enum ServerConfigStreamError {
    /// The underlying stream produced an error.
    ///
    /// This is used to wrap arbitrary stream provider errors.
    #[error("stream provider error")]
    StreamError(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The stream completed without yielding an initial [`ServerConfig`].
    ///
    /// [`ServerConfigProvider::start`] requires at least one item to seed
    /// the provider; otherwise startup fails with this error.
    #[error("empty stream")]
    EmptyStream,

    /// The builder failed to construct a stream.
    ///
    /// The provider will surface this when initial construction fails.
    #[error("could not build stream")]
    StreamBuilderError(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Error originating from [`rustls`] certificate verifier construction.
    #[error("cert verifier builder error")]
    VerifierBuilderError(#[from] VerifierBuilderError),

    /// The builder/stream did not provide a [`rustls::sign::CertifiedKey`]
    #[error("missing server certified key")]
    MissingCertifiedKey,

    /// The builder/stream did not provide any root certificates resulting in an empty [`rustls::RootCertStore`]
    #[error("missing root certificates")]
    MissingRoots,

    /// Wrapper for any [`rustls::Error`] error.
    #[error("rustls error")]
    RustlsError(#[from] rustls::Error),
}

/// A factory for producing a stream of [`rustls::ServerConfig`].
///
/// Implement this trait to define how your application sources TLS configs
/// (e.g., file watchers, secret managers, pull-from-API).
///
/// The returned stream should yield *complete* [`ServerConfig`] values. Each
/// item replaces the provider's current config atomically (via [`ArcSwap`]).
///
/// # Contract
/// - [`build()`](ServerConfigStreamBuilder::build) should return a stream that eventually yields at least one
///   [`ServerConfig`] during initial startup. If it doesn't, startup will fail
///   with [`ServerConfigStreamError::EmptyStream`].
/// - On stream failure, the provider will call [`build()`](ServerConfigStreamBuilder::build) again with backoff.
/// - Items from the stream should be independent [`Arc<ServerConfig>`] values.
///
/// # Examples
/// ```no_run
/// use std::sync::Arc;
/// use rustls::ServerConfig;
/// use tokio_stream::{Stream, wrappers::ReceiverStream};
///
/// struct MyConfigProvider;
///
/// impl ServerConfigStreamBuilder for MyConfigProvider {
///     type ConfigStream = ReceiverStream<Result<Arc<ServerConfig>, ServerConfigStreamError>>;
///
///     async fn build(
///         &mut self,
///     ) -> Result<Self::ConfigStream, ServerConfigStreamError> {
///         // Construct a stream that yields ServerConfig updates.
///         // See the SPIFFE implementation in [`rustls-spiffe`] for a full example.
///         unimplemented!()
///     }
/// }
/// ```
pub trait ServerConfigStreamBuilder {
    /// The stream type produced by this builder.
    ///
    /// Each item is either a fresh [`ServerConfig`] or an error explaining why
    /// the update failed.
    type ConfigStream: Stream<Item = Result<Arc<ServerConfig>, ServerConfigStreamError>>
        + Send
        + Sync
        + Unpin
        + 'static;

    /// Asynchronously construct a new configuration stream.
    ///
    /// The provider will:
    /// - call this once during startup to obtain the initial stream,
    /// - read the *first* config to seed its state,
    /// - continue to poll the provided stream for new configs
    /// - upon stream failure or completion, call it again with
    ///   exponential backoff until a new stream is available.
    fn build(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Self::ConfigStream, ServerConfigStreamError>> + Send;
}

/// Holds the current [`ServerConfig`] and refreshes it from an async stream.
///
/// Internally uses [`ArcSwap<ServerConfig>`] to provide lock-free, atomic swaps
/// of the active TLS configuration. Call [`get_config`](Self::get_config) to
/// obtain an [`Arc<ServerConfig>`] for acceptors or handshakes.
///
/// Liveness of the underlying stream can be checked via
/// [`stream_healthy`](Self::stream_healthy).
///
/// # Concurrency
/// Reads [`get_config()`](Self::get_config) are wait-free and do not block updates.
/// Updates occur on a background task that listens to the user-provided stream.
///
/// # Backoff & Recovery
/// When the stream ends or errors, the provider:
/// - Marks itself unhealthy,
/// - Rebuilds the stream via the builder,
/// - Retries with exponential backoff starting at 10ms and capping at 10s,
/// - Resets backoff after a successful re-establishment.
///
/// # Examples
/// ```no_run
/// let config_stream_builder =
///     SpiffeServerConfigStream::builder(vec!["example.org".try_into().unwrap()]);
/// let config_provider = ServerConfigProvider::start(config_stream_builder)
///     .await
///     .unwrap();
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
///     .await
///     .unwrap();
///
/// loop {
///     let (stream, _) = listener.accept().await.unwrap();
///
///     let acceptor =
///         tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
///     tokio::pin!(acceptor);
///
///     let config_provider = config_provider.clone();
///     match acceptor.as_mut().await {
///         Ok(start) => {
///             tokio::spawn(async move {
///                 if !config_provider.stream_healthy() {
///                     warn!(
///                         "config provider does not have healthy stream; TLS config may be out of date"
///                     );
///                 }
///                 let config = config_provider.get_config();
///                 match start.into_stream(config).await {
///                     Ok(stream) => { /* serve some app (e.g. hyper, tower, axum) */ },
///                     Err(err) => { /* handle error */ }
///                 }
///             })
///         }
///         Err(_) => { /* handle error */ }
///     }
/// }
/// ```
pub struct ServerConfigProvider {
    /// The current, atomically-swappable server configuration.
    inner: ArcSwap<ServerConfig>,

    /// Health flag for the underlying stream (true = healthy).
    stream_healthy: AtomicBool,
}

impl ServerConfigProvider {
    /// Initializes the provider and spawn the background refresh task.
    ///
    /// This awaits the first item from the builder's stream to seed the
    /// internal configuration. It then spawns a task that continuously reads
    /// subsequent updates, atomically swapping them into place.
    ///
    /// On stream failure or completion, the task attempts to rebuild the
    /// stream using exponential backoff (initial 10ms, max 10s, doubling).
    ///
    /// Returns an [`Arc<ServerConfigProvider>`]
    ///
    /// # Errors
    /// - [`ServerConfigStreamError::EmptyStream`]: the initial stream yielded no item.
    /// - [`ServerConfigStreamError::StreamBuilderError`]: building the stream failed.
    /// - [`ServerConfigStreamError`] variants wrapping errors from your builder or `rustls`.
    pub async fn start<B>(mut builder: B) -> Result<Arc<Self>, ServerConfigStreamError>
    where
        B: ServerConfigStreamBuilder + Send + 'static,
    {
        let mut stream = builder.build().await?;
        let initial = stream
            .next()
            .await
            .ok_or(ServerConfigStreamError::EmptyStream)??;
        let this = Arc::new(Self {
            inner: ArcSwap::from(initial),
            stream_healthy: AtomicBool::new(true),
        });
        let ret = this.clone();

        tokio::spawn(async move {
            let initial_delay = Duration::from_millis(10);
            let mut delay = initial_delay;
            let max_delay = Duration::from_secs(10);
            loop {
                match stream.next().await {
                    Some(Ok(server_config)) => {
                        this.inner.store(server_config);

                        #[cfg(feature = "tracing")]
                        debug!(name: "server_config_provider", "stored updated server config from stream");
                    }
                    Some(Err(_)) | None => {
                        this.stream_healthy.store(false, Ordering::Relaxed);

                        #[cfg(feature = "tracing")]
                        error!("config stream returned error or none, trying to build new stream");

                        match builder.build().await {
                            Ok(s) => {
                                this.stream_healthy.store(true, Ordering::Relaxed);
                                delay = initial_delay;
                                stream = s;

                                #[cfg(feature = "tracing")]
                                info!(name: "server_config_provider", "reestablished server config stream");
                            }
                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                error!(name: "server_config_provider", retry_in_ms = delay.as_millis(), error = %err, "failed to reestablish server config stream");

                                sleep(delay).await;
                                delay = (delay * 2).min(max_delay);
                            }
                        };
                    }
                }
            }
        });
        Ok(ret)
    }

    /// Returns whether the stream is currently healthy.
    ///
    /// This flag is set to `false` when the stream errors or ends, and set
    /// back to `true` after a successful rebuild.
    pub fn stream_healthy(&self) -> bool {
        self.stream_healthy.load(Ordering::Relaxed)
    }

    /// Get the current [`ServerConfig`].
    ///
    /// This is a cheap, lock-free read that loads the internal [`ArcSwap<ServerConfig>`] into an [`Arc<ServerConfig>`]
    /// Callers can hold onto the returned [`Arc<ServerConfig>`] as long as
    /// needed; updates will affect future calls, not the already-held value.
    pub fn get_config(&self) -> Arc<ServerConfig> {
        self.inner.load_full()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rustls::ServerConfig;
    use thiserror::Error;
    use tokio::sync::{Mutex, mpsc};
    use tokio_stream::wrappers::ReceiverStream;

    use crate::{ServerConfigProvider, ServerConfigStreamBuilder, ServerConfigStreamError};

    #[derive(Error, Debug)]
    struct MockError(&'static str);
    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    #[derive(Debug)]
    struct NoopResolver;
    impl rustls::server::ResolvesServerCert for NoopResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    fn empty_server_config() -> Arc<ServerConfig> {
        Arc::from(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::from(NoopResolver)),
        )
    }

    #[derive(Debug)]
    struct MockServerConfigStreamBuilder {
        streams:
            Mutex<VecDeque<mpsc::Receiver<Result<Arc<ServerConfig>, ServerConfigStreamError>>>>,
        builds: Arc<AtomicUsize>,
    }

    impl MockServerConfigStreamBuilder {
        fn new(
            streams: Vec<mpsc::Receiver<Result<Arc<ServerConfig>, ServerConfigStreamError>>>,
        ) -> Self {
            let builds = Arc::from(AtomicUsize::new(0));
            let streams = Mutex::from(VecDeque::from(streams));
            Self { streams, builds }
        }
    }

    impl ServerConfigStreamBuilder for MockServerConfigStreamBuilder {
        type ConfigStream = ReceiverStream<Result<Arc<ServerConfig>, ServerConfigStreamError>>;

        async fn build(&mut self) -> Result<Self::ConfigStream, ServerConfigStreamError> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            let rx = self.streams.lock().await.pop_front().ok_or_else(|| {
                ServerConfigStreamError::StreamBuilderError(MockError("mock stream error").into())
            })?;
            Ok(ReceiverStream::new(rx))
        }
    }

    #[tokio::test]
    async fn start_fails_given_initial_stream_build_failure() {
        let builder = MockServerConfigStreamBuilder::new(vec![]);

        let res = ServerConfigProvider::start(builder).await;
        match res {
            Err(ServerConfigStreamError::StreamBuilderError(_)) => { /* test pass */ }
            _ => panic!("expected ServerConfigStreamError::EmptyStream"),
        }
    }

    #[tokio::test]
    async fn start_fails_when_stream_is_empty() {
        let (tx, rx) = mpsc::channel(1);

        // drop tx so stream returns Poll::Ready(None)
        std::mem::drop(tx);

        let builder = MockServerConfigStreamBuilder::new(vec![rx]);

        let res = ServerConfigProvider::start(builder).await;
        match res {
            Err(ServerConfigStreamError::EmptyStream) => { /* test pass */ }
            _ => panic!("expected ServerConfigStreamError::EmptyStream"),
        }
    }

    #[tokio::test]
    async fn start_fails_when_first_result_is_err() {
        let (tx, rx) = mpsc::channel(1);
        let builder = MockServerConfigStreamBuilder::new(vec![rx]);

        tx.send(Err(ServerConfigStreamError::StreamError(
            MockError("fake error").into(),
        )))
        .await
        .unwrap();

        let res = ServerConfigProvider::start(builder).await;
        match res {
            Err(ServerConfigStreamError::StreamError(err)) => {
                assert_eq!(err.to_string(), "fake error");
            }
            _ => panic!("expected ServerConfigStreamError::EmptyStream"),
        }
    }

    #[tokio::test]
    async fn start_and_initial_config_is_loaded() {
        let (tx, rx) = mpsc::channel(1);
        let builder = MockServerConfigStreamBuilder::new(vec![rx]);
        let expected = empty_server_config();
        tx.send(Ok(expected.clone())).await.unwrap();
        let provider = ServerConfigProvider::start(builder).await.unwrap();

        let got = provider.get_config();

        assert!(Arc::ptr_eq(&got, &expected));
        assert!(provider.stream_healthy());
    }

    #[tokio::test]
    async fn single_stream_config_hot_swap() {
        let (tx, rx) = mpsc::channel(1);
        let builder = MockServerConfigStreamBuilder::new(vec![rx]);

        let initial = empty_server_config();
        tx.send(Ok(initial.clone())).await.unwrap();
        let provider = ServerConfigProvider::start(builder).await.unwrap();
        let got = provider.get_config();
        assert!(Arc::ptr_eq(&got, &initial));
        assert!(provider.stream_healthy());

        for i in 0..10 {
            let expected = empty_server_config();
            tx.send(Ok(expected.clone())).await.unwrap();

            tokio::task::yield_now().await;
            let got = provider.get_config();
            assert!(
                Arc::ptr_eq(&got, &expected),
                "config not updated on iter {i}"
            );
            assert!(provider.stream_healthy());
        }
    }

    #[tokio::test]
    async fn stream_failure_triggers_rebuild() {
        let (tx1, rx1) = mpsc::channel(1);
        let (tx2, rx2) = mpsc::channel(1);
        let builder = MockServerConfigStreamBuilder::new(vec![rx1, rx2]);
        let builds = &builder.builds.clone();
        let initial = empty_server_config();
        tx1.send(Ok(initial.clone())).await.unwrap();
        let provider = ServerConfigProvider::start(builder).await.unwrap();
        assert!(Arc::ptr_eq(&provider.get_config(), &initial));
        assert!(provider.stream_healthy());

        tx1.send(Err(ServerConfigStreamError::StreamError(
            MockError("fake error").into(),
        )))
        .await
        .unwrap();

        // polling to assert provider.stream_healthy
        // goes to false proved to be flaky due to it
        // going back to healthy too fast.

        // check that it rebuilt the stream via the provider
        tokio::task::yield_now().await;
        assert_eq!(builds.load(Ordering::SeqCst), 2);

        // push a new config and check that it's loaded
        let new = empty_server_config();
        tx2.send(Ok(new.clone())).await.unwrap();
        tokio::task::yield_now().await;

        // check that stream is healthy and new config was loaded
        assert!(provider.stream_healthy());
        assert!(Arc::ptr_eq(&provider.get_config(), &new))
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stream_rebuild_goes_into_backoff() {
        let (tx, rx) = mpsc::channel(1);
        let builder = MockServerConfigStreamBuilder::new(vec![rx]);
        let builds = &builder.builds.clone();
        let initial = empty_server_config();
        tx.send(Ok(initial.clone())).await.unwrap();
        let provider = ServerConfigProvider::start(builder).await.unwrap();
        assert!(Arc::ptr_eq(&provider.get_config(), &initial));
        assert!(provider.stream_healthy());
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        tx.send(Err(ServerConfigStreamError::StreamError(
            MockError("fake error").into(),
        )))
        .await
        .unwrap();
        tokio::task::yield_now().await;
        // assert it tried to rebuild stream but is still unhealthy since
        // the MockServerConfigBuilder will return an error as the streams
        // vector is empty.
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert!(!provider.stream_healthy.load(Ordering::Relaxed));
    }
}
