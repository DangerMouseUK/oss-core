#![no_main]
//! Core `0x00` transport packets: decode, and re-encode what decodes.

use libfuzzer_sys::fuzz_target;
use oss_proto::CorePacket;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = CorePacket::decode(data) {
        let bytes = p.to_bytes();
        let again = CorePacket::decode(&bytes).expect("re-encoded core packet decodes");
        assert_eq!(again, p, "bytes {bytes:02x?}");
    }
});
