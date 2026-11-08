//! Greets players as they enter and answers `!ping`.
//!
//! ```sh
//! cargo run -p oss-bot-sdk --example greeter -- 127.0.0.1:5000 GreeterBot password [arena]
//! ```

use oss_bot_sdk::{BotConfig, BotEvent, Handler, Session};

struct Greeter {
    pings: u32,
}

impl Handler for Greeter {
    fn on_event(&mut self, bot: &mut Session, event: BotEvent) {
        match event {
            BotEvent::EnteredArena => {
                let others = bot.players().count().saturating_sub(1);
                println!("in the arena with {others} other player(s)");
            }
            // Players arriving after the bot (not the ones already there).
            BotEvent::PlayerEntered {
                player,
                initial: false,
            } => {
                let text = format!("Welcome, {}! Say !ping to test me.", player.name);
                bot.send_private(player.pid, &text);
            }
            BotEvent::Chat(msg) if msg.text.trim().eq_ignore_ascii_case("!ping") => {
                self.pings += 1;
                bot.reply(&msg, &format!("pong #{}", self.pings));
            }
            BotEvent::LoginFailed { reason, .. } => eprintln!("login failed: {reason}"),
            BotEvent::Disconnected(reason) => println!("disconnected: {reason:?}"),
            _ => {}
        }
    }
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(server), Some(name), Some(password)) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: greeter <host:port> <name> <password> [arena]");
        std::process::exit(2);
    };
    let mut config = BotConfig::new(name, password);
    if let Some(arena) = args.next() {
        config = config.arena(arena);
    }
    oss_bot_sdk::run(server, config, &mut Greeter { pings: 0 })?;
    Ok(())
}
