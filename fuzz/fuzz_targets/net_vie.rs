#![no_main]
//! VIE: arbitrary keys and datagrams. Decrypting must not panic, and
//! encrypt → decrypt must give back the plaintext.

use libfuzzer_sys::fuzz_target;
use oss_net::VieCipher;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let key = u32::from_le_bytes(data[..4].try_into().unwrap());
    let body = &data[4..];
    let Some(cipher) = VieCipher::new(key) else {
        return;
    };
    let mut garbage = body.to_vec();
    cipher.decrypt(&mut garbage);

    let mut buf = body.to_vec();
    cipher.encrypt(&mut buf);
    cipher.decrypt(&mut buf);
    assert_eq!(buf, body);
});
