//! A bot's password must not reach a log through `Debug`.
//!
//! [`BotConfig`] is the likeliest of all of these to escape: printing your own
//! configuration while working out why a bot will not log in is an obvious
//! thing to do, and the password sits right next to the name.

use oss_bot_sdk::BotConfig;

const SECRET: &str = "hunter2-swordfish";

#[test]
fn bot_config_does_not_print_its_password() {
    let config = BotConfig::new("testbot", SECRET);
    let rendered = format!("{config:?}");

    assert!(
        !rendered.contains(SECRET),
        "the password reached Debug output: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "nothing marks where the password was: {rendered}"
    );
    // Redaction must not blind debugging: the rest still prints.
    for field in ["BotConfig", "testbot", "arena", "ship", "encryption"] {
        assert!(rendered.contains(field), "{field} missing from {rendered}");
    }
}
