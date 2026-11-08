#![no_main]
//! Every client-to-server game packet: decode, and re-encode what decodes.
//!
//! The position encoder always writes a fresh checksum (by design), so a
//! received packet with a wrong checksum comes back with the right one.

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::assert_stable;
use oss_proto::C2SPacket;
use oss_proto::wire::Packet;

fuzz_target!(|data: &[u8]| {
    let Ok(mut p) = C2SPacket::decode(data) else {
        return;
    };
    if let C2SPacket::Position(pos) = &mut p {
        let fresh = C2SPacket::decode(&pos.to_bytes()).unwrap();
        let C2SPacket::Position(fresh) = fresh else {
            panic!("position re-decoded as {fresh:?}")
        };
        assert!(fresh.checksum_ok());
        pos.checksum = fresh.checksum;
    }
    assert_stable(&p, C2SPacket::to_bytes, C2SPacket::decode);
});
