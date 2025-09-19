# rustls-config-stream

[![Version](https://img.shields.io/crates/v/rustls-config-stream)](https://crates.io/crates/rustls-config-stream)
[![Tests](https://github.com/dsykes16/rustls-config-stream/actions/workflows/test.yml/badge.svg)](https://github.com/dsykes16/rustls-config-stream/actions/workflows/test.yml)
[![Docs](https://img.shields.io/docsrs/rustls-config-stream)](https://docs.rs/rustls-config-stream/latest/rustls_config_stream/)
[![CodeCov](https://codecov.io/gh/dsykes16/rustls-config-stream/graph/badge.svg?token=SJFGDZMV3J)](https://codecov.io/gh/dsykes16/rustls-config-stream)
[![License](https://img.shields.io/crates/l/rustls-config-stream)](https://github.com/dsykes16/rustls-config-stream/blob/main/LICENSE)
[![Dependencies](https://deps.rs/repo/github/dsykes16/rustls-config-stream/status.svg)](https://deps.rs/repo/github/dsykes16/rustls-config-stream)
[![CodeFactor](https://www.codefactor.io/repository/github/dsykes16/rustls-config-stream/badge)](https://www.codefactor.io/repository/github/dsykes16/rustls-config-stream)

[`rustls::ServerConfig`] and [`rustls::ClientConfig`] providers backed async streams.

This module exposes a [`ServerConfigProvider`] and [`ClientConfigProvider`].
Both function identically, holding the current config in an
[`ArcSwap`](arc_swap::ArcSwap), providing a `get_config()` method to load the
current config as a standard [`Arc`](std::sync::Arc), and storing a new config
when it arrives from a user-supplied stream via a [`ServerConfigStreamBuilder`]
or [`ClientConfigStreamBuilder`].

The background task performs exponential backoff (10ms -> 10s, doubling)
when the stream fails, and attempts to re-create the stream via the builder.

## Usage

- Implement [`ServerConfigStreamBuilder`] to produce a stream of fresh
  `ServerConfig` instances (e.g. reading from disk, a secret store, or
  watching a certificate manager).
- Start the provider with [`ServerConfigProvider::start`].
- Use [`ServerConfigProvider::get_config`] wherever you need the current
  config (e.g. inside an acceptor loop).
- Optionally monitor liveness via [`ServerConfigProvider::stream_healthy`].
- [`ClientConfigProvider`] works identically, only for [`rustls::ClientConfig`]
  instead of [`rustls::ServerConfig`].

## Tracing

If the `tracing` feature is enabled, the provider will emit diagnostics
(debug/info/error) about updates and reconnection attempts.
