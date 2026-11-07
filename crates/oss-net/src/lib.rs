//! Sans-IO transport for the SubSpace protocol.
//!
//! Implements the core (`0x00`-prefixed) layer: connection setup, reliable delivery,
//! acknowledgements, clustering, chunked and sized transfers, time sync and the
//! pluggable packet ciphers. Callers feed datagrams in and pull datagrams out; the
//! same state machine serves clients, servers and bots, native and wasm.

pub mod vie;

pub use vie::VieCipher;
