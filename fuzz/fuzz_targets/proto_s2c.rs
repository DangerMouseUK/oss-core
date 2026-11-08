#![no_main]
//! Every server-to-client game packet (settings included): decode, and
//! re-encode what decodes.
//!
//! The weapon encoder always writes a fresh checksum (by design), so a received
//! packet with a wrong checksum comes back with the right one.

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::assert_stable;
use oss_proto::S2CPacket;
use oss_proto::wire::Packet;

fuzz_target!(|data: &[u8]| {
    let Ok(mut p) = S2CPacket::decode(data) else {
        return;
    };
    if let S2CPacket::Weapon(w) = &mut p {
        let S2CPacket::Weapon(fresh) = S2CPacket::decode(&w.to_bytes()).unwrap() else {
            panic!("weapon packet re-decoded as another type")
        };
        assert!(fresh.checksum_ok());
        w.checksum = fresh.checksum;
    }
    assert_stable(&p, S2CPacket::to_bytes, S2CPacket::decode);
});
