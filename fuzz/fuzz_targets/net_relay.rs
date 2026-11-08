#![no_main]
//! WebSocket relay framing: single frames must re-encode to the same frame, and
//! a byte stream must decode the same however it is split.

use libfuzzer_sys::fuzz_target;
use oss_net::relay::{Frame, StreamDecoder};

fn frames<'a>(chunks: impl Iterator<Item = &'a [u8]>) -> Vec<Result<Vec<u8>, String>> {
    let mut dec = StreamDecoder::new();
    let mut out = Vec::new();
    for chunk in chunks {
        dec.push(chunk);
        while let Some(f) = dec.next_frame() {
            match f {
                Ok(f) => {
                    let mut b = Vec::new();
                    f.encode(&mut b).expect("decoded frames re-encode");
                    out.push(Ok(b));
                }
                Err(e) => out.push(Err(e.to_string())),
            }
            if dec.is_broken() {
                return out;
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = Frame::decode(data) {
        let mut b = Vec::new();
        f.encode(&mut b).expect("decoded frames re-encode");
        assert_eq!(Frame::decode(&b), Ok(f));
    }
    let Some((&split, stream)) = data.split_first() else {
        return;
    };
    let whole = frames(core::iter::once(stream));
    let pieces = frames(stream.chunks(usize::from(split.max(1))));
    assert_eq!(whole, pieces);
});
