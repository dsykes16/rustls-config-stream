# rustls-config-stream

[![Tests](https://github.com/dsykes16/rustls-config-stream/actions/workflows/test.yml/badge.svg)](https://github.com/dsykes16/rustls-config-stream/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/dsykes16/rustls-config-stream/graph/badge.svg?token=SJFGDZMV3J)](https://codecov.io/gh/dsykes16/rustls-config-stream)
[![Crates.io License](https://img.shields.io/crates/l/rustls-config-stream)](https://github.com/dsykes16/rustls-config-stream/blob/main/LICENSE)
[![dependency status](https://deps.rs/repo/github/dsykes16/rustls-config-stream/status.svg)](https://deps.rs/repo/github/dsykes16/rustls-config-stream)
[![CodeFactor](https://www.codefactor.io/repository/github/dsykes16/rustls-config-stream/badge)](https://www.codefactor.io/repository/github/dsykes16/rustls-config-stream)

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
