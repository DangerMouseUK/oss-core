//! Wire types and codecs for the SubSpace/Continuum game protocol.
//!
//! Everything here is pure data: no sockets, no clocks. Decoding never panics on
//! malformed input; it returns an error instead.
