#![no_main]
//! `.ossr` replays: parse, then rewrite (plain and compressed) and parse back.

use libfuzzer_sys::fuzz_target;
use oss_formats::Replay;

fuzz_target!(|data: &[u8]| {
    let Ok(replay) = Replay::parse(data) else {
        return;
    };
    let _ = replay.meta().count();
    let _ = replay.files().count();
    let end = replay.duration_ms();
    assert!(replay.seek(end) <= replay.records.len());
    assert!(replay.seek(0) <= replay.records.len());
    for compress in [false, true] {
        let again = Replay::parse(&replay.to_bytes(compress)).expect("rewritten replay parses");
        assert_eq!(again.records, replay.records);
        assert!(!again.truncated);
    }
});
