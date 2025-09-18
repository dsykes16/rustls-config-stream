# rustls-config-stream

[`rustls::ServerConfig`] provider backed by an async stream.

This module exposes a [`ServerConfigProvider`] that holds the "current"
TLS server configuration and updates it whenever a new config arrives from a
user-supplied stream (see [`ServerConfigStreamBuilder`]).

The background task performs exponential backoff (10ms -> 10s, doubling)
when the stream fails, and attempts to re-create the stream via the builder.
Call [`ServerConfigProvider::get_config`] whenever you need an [`Arc<ServerConfig>`].

## Usage

- Implement [`ServerConfigStreamBuilder`] to produce a stream of fresh
  `ServerConfig` instances (e.g. reading from disk, a secret store, or
  watching a certificate manager).
- Start the provider with [`ServerConfigProvider::start`].
- Use [`ServerConfigProvider::get_config`] wherever you need the current
  config (e.g. inside an acceptor loop).
- Optionally monitor liveness via [`ServerConfigProvider::stream_healthy`].

## Tracing

If the `tracing` feature is enabled, the provider will emit diagnostics
(debug/info/error) about updates and reconnection attempts.
