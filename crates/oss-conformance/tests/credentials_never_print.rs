//! The conformance runner's login password must not reach a log through
//! `Debug`. It is a real account's password whenever someone points the suite
//! at a live zone with `--password`.

use oss_conformance::live::ServerOptions;

const SECRET: &str = "hunter2-swordfish";

#[test]
fn server_options_does_not_print_its_password() {
    let opts = ServerOptions {
        name: Some("conformance".into()),
        password: SECRET.into(),
        ..Default::default()
    };
    let rendered = format!("{opts:?}");

    assert!(
        !rendered.contains(SECRET),
        "the password reached Debug output: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "nothing marks where the password was: {rendered}"
    );
    // Redaction must not blind debugging: the rest still prints.
    for field in ["ServerOptions", "conformance", "arena", "timeout"] {
        assert!(rendered.contains(field), "{field} missing from {rendered}");
    }
}
