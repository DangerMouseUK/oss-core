#![no_main]
//! Billing and directory protocol packets. The first byte picks the decoder.

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::assert_stable;
use oss_proto::billing::{BillerToServer, ServerToBiller};
use oss_proto::directory::{DirPing, DirPong, ZoneList, ZoneListRequest, ZoneUpdate};

macro_rules! check {
    ($t:ty, $data:expr) => {
        if let Ok(p) = <$t>::decode($data) {
            assert_stable(
                &p,
                |p| {
                    let mut v = Vec::new();
                    p.encode(&mut v);
                    v
                },
                <$t>::decode,
            );
        }
    };
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, data)) = data.split_first() else {
        return;
    };
    match which % 7 {
        0 => check!(ServerToBiller, data),
        1 => check!(BillerToServer, data),
        2 => check!(ZoneUpdate, data),
        3 => check!(DirPing, data),
        4 => check!(DirPong, data),
        5 => check!(ZoneListRequest, data),
        _ => check!(ZoneList, data),
    }
});
