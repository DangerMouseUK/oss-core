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

## Encryption

A bot connects with VIE by default, which every server accepts. The security mechanisms it can speak are in `config.mechanisms`, a registry holding the built-in ones (None, Subspace and OpenSecurity), and `config.encryption` says which to use:

- `Encryption::named("vie")`, the default: that one mechanism and nothing else. Short names (`none`, `vie`, `opensec`) match in any case; anyone else's are `name@their-domain` and match exactly.
- `Encryption::Automatic`: every mechanism that may be tried automatically, strongest first, stepping down to the next after one second without an answer. With the built-ins that is OpenSecurity, then Subspace.

A mechanism from elsewhere, including one supplied by a private module, is added with one line, after which both choices can reach it:

```rust,no_run
use oss_bot_sdk::{BotConfig, Encryption, Mechanism};

# fn mechanism() -> Mechanism {
#     use oss_net::{Era, Selection};
#     Mechanism::new("example@example.org", "Example", Era::Modern, 4000, Selection::Automatic)
#         .unwrap()
# }
let mut config = BotConfig::new("PingBot", "secret").encryption(Encryption::Automatic);
config.mechanisms.register(mechanism())?;
println!("{}", config.mechanisms.supported_line());
# Ok::<(), oss_bot_sdk::MechanismError>(())
```

A server key on record is given with `config.pinned(MechanismId::new("opensec")?, key)`. **It does not choose the mechanism**: with `Encryption::Automatic` the bot then tries that mechanism alone, and never steps down from it; with `Encryption::named("opensec")` it uses the key; with the default, VIE by name, the key is not used.

**Changed in this release:** `Encryption` used to be the closed list `Vie`, `OpenSec { pinned }` and `OpenSecOrVie`, and `Session::new` could not fail. `Vie` is now `Encryption::named("vie")` (the default); `OpenSec { pinned: None }` is `Encryption::named("opensec")`; `OpenSec { pinned: Some(key) }` is `Encryption::Automatic` (or `named("opensec")`) with `.pinned(MechanismId::new("opensec")?, key)`; `OpenSecOrVie` is `Encryption::Automatic`. `Session::new` returns a `Result`, refusing a mechanism the registry does not hold, and `run` reports that as an `InvalidInput` error. See `docs/CHANGELOG.md`.

Licence: MIT.
