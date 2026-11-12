//! Passwords must not reach a log through `Debug`.
//!
//! Every packet here carries a credential in an ordinary `FixedStr`, whose own
//! `Debug` prints what it holds — correct for names, arenas and filenames, and
//! wrong for exactly these fields. Each owning type writes its `Debug` by hand
//! and prints [`oss_proto::wire::Redacted`] instead.
//!
//! Each check asserts three things, not one: the secret is absent, the marker
//! is present, and a neighbouring field still prints. The third matters as much
//! as the first — redaction that blanked the whole packet would pass a
//! secret-is-absent test while making the type useless to debug with.

use oss_proto::billing::{ServerToBiller, UserLogin};
use oss_proto::c2s::Login;
use oss_proto::directory::ZoneUpdate;
use oss_proto::wire::FixedStr;

/// Distinctive enough that it cannot appear in a `Debug` rendering by accident.
const SECRET: &str = "hunter2-swordfish";

fn redacted(rendered: &str, visible: &[&str]) {
    assert!(
        !rendered.contains(SECRET),
        "the password reached Debug output: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "nothing marks where the password was: {rendered}"
    );
    for v in visible {
        assert!(
            rendered.contains(v),
            "{v} should still print -- redaction must not blind debugging: {rendered}"
        );
    }
}

#[test]
fn login_does_not_print_the_players_password() {
    let login = Login {
        kind: 0x09,
        flags: 0,
        name: FixedStr::from("player"),
        password: FixedStr::from(SECRET),
        machine_id: 0x1234_5678,
        connect_type: 4,
        timezone_bias: 0,
        unknown1: 0,
        client_version: 134,
        field444: 444,
        field555: 555,
        permission_id: 0,
        reserved: [0; 12],
        cont_id: None,
    };
    redacted(
        &format!("{login:?}"),
        &["player", "machine_id", "305419896"],
    );
}

#[test]
fn user_login_does_not_print_the_players_password_to_the_biller() {
    let login = UserLogin {
        name: FixedStr::from("player"),
        password: FixedStr::from(SECRET),
        connection_id: 7,
        ..Default::default()
    };
    redacted(&format!("{login:?}"), &["player", "connection_id"]);
}

#[test]
fn server_connect_does_not_print_the_zones_biller_password() {
    let connect = ServerToBiller::ServerConnect {
        server_id: 1,
        group_id: 2,
        score_id: 3,
        name: FixedStr::from("Test Zone"),
        port: 5000,
        password: FixedStr::from(SECRET),
    };
    redacted(&format!("{connect:?}"), &["Test Zone", "5000", "score_id"]);
}

#[test]
fn zone_update_does_not_print_the_directory_password() {
    let update = ZoneUpdate {
        port: 5000,
        players: 12,
        name: FixedStr::from("Test Zone"),
        password: FixedStr::from(SECRET),
        description: b"a zone".to_vec(),
        ..Default::default()
    };
    redacted(&format!("{update:?}"), &["Test Zone", "5000", "players"]);
}

/// `ServerToBiller`'s `Debug` is written out by hand so one variant can redact,
/// which means the other eighteen are transcribed rather than derived. This
/// checks a spread of them still render their own name and fields, so a
/// mis-transcription shows up as a failing test rather than as a confusing log
/// line much later.
#[test]
fn the_other_biller_variants_still_print_in_full() {
    assert_eq!(format!("{:?}", ServerToBiller::Ping), "Ping");
    assert_eq!(
        format!("{:?}", ServerToBiller::ServerDisconnect),
        "ServerDisconnect"
    );

    let logoff = format!(
        "{:?}",
        ServerToBiller::UserLogoff {
            connection_id: 9,
            reason: 1,
            latency: 20,
            ping: 30,
            loss_s2c: 0,
            loss_c2s: 0,
            score: None,
        }
    );
    for field in [
        "UserLogoff",
        "connection_id",
        "reason",
        "latency",
        "ping",
        "loss_s2c",
        "loss_c2s",
        "score",
    ] {
        assert!(logoff.contains(field), "{field} missing from {logoff}");
    }

    let chat = format!(
        "{:?}",
        ServerToBiller::UserChannelChat {
            connection_id: 9,
            channel: FixedStr::from("staff"),
            text: b"hello".to_vec(),
        }
    );
    assert!(
        chat.contains("UserChannelChat") && chat.contains("staff"),
        "{chat}"
    );

    let unknown = format!(
        "{:?}",
        ServerToBiller::Unknown {
            kind: 0x7F,
            data: vec![1, 2, 3],
        }
    );
    assert!(
        unknown.contains("Unknown") && unknown.contains("127"),
        "{unknown}"
    );

    // The wrapped form: UserLogin's own Debug does the redacting here.
    let wrapped = format!(
        "{:?}",
        ServerToBiller::UserLogin(UserLogin {
            password: FixedStr::from(SECRET),
            ..Default::default()
        })
    );
    assert!(!wrapped.contains(SECRET), "{wrapped}");
    assert!(wrapped.starts_with("UserLogin("), "{wrapped}");
}
