// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#![doc = include_str!("../README.md")]
#![forbid(rust_2018_idioms)]
#![forbid(missing_docs, unsafe_code)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::nursery,
    clippy::dbg_macro,
    clippy::todo
)]

mod client;
mod server;

pub use client::{ClientConfigProvider, ClientConfigStreamBuilder, ClientConfigStreamError};

pub use server::{ServerConfigProvider, ServerConfigStreamBuilder, ServerConfigStreamError};
