# oss-bot-sdk

Write SubSpace/Continuum zone bots in a few lines. Part of [Open SubSpace](https://github.com/DangerMouseUK/oss-core).

A bot is a handler that reacts to events: players entering and leaving, chat, kills, ship and team changes, and positions. It acts through the session: chat, changing ship or team, moving. The SDK takes care of the transport, the login, entering the arena, the player list, position updates and the server's security checks.

```rust,no_run
use oss_bot_sdk::{BotConfig, BotEvent, Session};

let config = BotConfig::new("PingBot", "secret");
oss_bot_sdk::run("127.0.0.1:5000", config, &mut |bot: &mut Session, event| {
    match event {
        BotEvent::PlayerEntered { player, initial: false } => {
            bot.send_private(player.pid, &format!("Welcome, {}!", player.name));
        }
        BotEvent::Chat(msg) if msg.text == "!ping" => bot.reply(&msg, "pong"),
        _ => {}
    }
})?;
# Ok::<(), std::io::Error>(())
```

A complete example is in `examples/greeter.rs`:

```sh
cargo run -p oss-bot-sdk --example greeter -- 127.0.0.1:5000 GreeterBot password
```

`Session` does no I/O itself, so the same bot can run in tests, simulations or your own event loop. `run` is a ready-made blocking UDP loop.

Bots connect with VIE by default, which every server accepts. `Encryption::OpenSec` and `Encryption::OpenSecOrVie` use OpenSec on servers that support it.

Licence: MIT.
