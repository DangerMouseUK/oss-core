//! A browser client: `oss-net` compiled to WebAssembly, connecting through the
//! WebSocket relay (`docs/protocol/websocket-relay.md`) to an echo zone.
//!
//! It opens the WebSocket with the `oss-relay.1` subprotocol, sends `Hello`,
//! and on `Welcome` starts an ordinary `Connection`: OpenSec, falling back to
//! VIE. Once connected it sends 50 small packets and one big one, and reports
//! on the page when all have come back in order.
//!
//! ```sh
//! cargo build --release --target wasm32-unknown-unknown -p oss-net --example browser
//! wasm-bindgen --target web --out-dir crates/oss-net/examples/browser/pkg \
//!     target/wasm32-unknown-unknown/release/examples/browser.wasm
//! cargo run -p oss-net --example relay_echo -- 127.0.0.1:5700
//! # serve crates/oss-net/examples/browser/ over HTTP and open index.html
//! ```
//!
//! On other targets this example builds to nothing.

#[cfg(target_arch = "wasm32")]
mod web {
    use std::cell::RefCell;
    use std::rc::Rc;

    use oss_net::opensec::{OpenSecClientHandshake, os_entropy};
    use oss_net::relay::{Frame, SUBPROTOCOL, VERSION};
    use oss_net::{Config, Connection, Event, Fallback, VieClientHandshake};
    use wasm_bindgen::JsCast;
    use wasm_bindgen::prelude::*;
    use web_sys::{BinaryType, MessageEvent, WebSocket};

    struct App {
        ws: WebSocket,
        conn: Option<Connection>,
        start: f64,
        sent: bool,
        expected: Vec<Vec<u8>>,
        echoed: usize,
        done: bool,
    }

    fn status(text: &str) {
        web_sys::console::log_1(&text.into());
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id("status"))
        {
            el.set_text_content(Some(text));
        }
    }

    fn send_frame(ws: &WebSocket, f: &Frame<'_>) {
        let mut b = Vec::new();
        f.encode(&mut b).expect("valid frame");
        let _ = ws.send_with_u8_array(&b);
    }

    impl App {
        fn now(&self) -> u64 {
            (js_sys::Date::now() - self.start).max(0.0) as u64
        }

        fn pump(&mut self) {
            let now = self.now();
            let Some(conn) = self.conn.as_mut() else {
                return;
            };
            conn.tick(now);
            if conn.is_connected() && !self.sent {
                for p in &self.expected {
                    conn.send(p, true);
                }
                self.sent = true;
                status(&format!(
                    "connected ({:?}); sending {} packets through the relay",
                    conn.cipher_kind(),
                    self.expected.len()
                ));
            }
            while let Some(d) = conn.poll_transmit() {
                send_frame(&self.ws, &Frame::Datagram(&d));
                conn.recycle(d);
            }
            while let Some(e) = conn.poll_event() {
                match e {
                    Event::Packet(p) => {
                        if self.done {
                            continue;
                        }
                        if self.expected.get(self.echoed) != Some(&p) {
                            status(&format!("FAIL: packet {} came back wrong", self.echoed));
                            self.done = true;
                            continue;
                        }
                        self.echoed += 1;
                        if self.echoed == self.expected.len() {
                            self.done = true;
                            status(&format!(
                                "PASS: {} packets (one of 3000 bytes) echoed through the WebSocket relay, encryption {:?}",
                                self.echoed,
                                conn.cipher_kind()
                            ));
                        }
                    }
                    Event::Disconnected(reason) => {
                        status(&format!("disconnected: {reason:?}"));
                        self.done = true;
                    }
                    _ => {}
                }
            }
        }
    }

    #[wasm_bindgen(start)]
    pub fn start() -> Result<(), JsValue> {
        let window = web_sys::window().ok_or("no window")?;
        // ?relay=ws://host:port overrides the default relay address.
        let search = window.location().search().unwrap_or_default();
        let url = search
            .trim_start_matches('?')
            .split('&')
            .find_map(|kv| kv.strip_prefix("relay="))
            .map(str::to_owned)
            .unwrap_or_else(|| "ws://127.0.0.1:5700".into());
        status(&format!("connecting to {url}"));
        let ws = WebSocket::new_with_str(&url, SUBPROTOCOL)?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let mut expected: Vec<Vec<u8>> = (0..50u8).map(|i| vec![0x40, i, i, i]).collect();
        let mut big: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        big[0] = 0x41;
        expected.push(big);
        let app = Rc::new(RefCell::new(App {
            ws: ws.clone(),
            conn: None,
            start: js_sys::Date::now(),
            sent: false,
            expected,
            echoed: 0,
            done: false,
        }));

        let onopen = {
            let ws = ws.clone();
            Closure::<dyn FnMut()>::new(move || {
                send_frame(
                    &ws,
                    &Frame::Hello {
                        version: VERSION,
                        zone: "",
                    },
                );
            })
        };
        ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
        onopen.forget();

        let onmessage = {
            let app = app.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                let Ok(buf) = e.data().dyn_into::<js_sys::ArrayBuffer>() else {
                    return;
                };
                let bytes = js_sys::Uint8Array::new(&buf).to_vec();
                let mut a = app.borrow_mut();
                match Frame::decode(&bytes) {
                    Ok(Frame::Welcome { .. }) if a.conn.is_none() => {
                        let now = a.now();
                        let handshake = Fallback::new(
                            Box::new(OpenSecClientHandshake::new(&os_entropy(), None)),
                            Box::new(VieClientHandshake::new(
                                js_sys::Math::random().to_bits() as u32
                            )),
                            1_000,
                        );
                        a.conn = Some(Connection::client(
                            Config::client(),
                            Box::new(handshake),
                            now,
                        ));
                        status("relay session open; connecting to the zone");
                    }
                    Ok(Frame::Datagram(d)) => {
                        let now = a.now();
                        if let Some(c) = a.conn.as_mut() {
                            c.handle_datagram(now, d);
                        }
                    }
                    Ok(Frame::Close { reason, message }) => {
                        status(&format!("relay closed the session: {reason:?} {message}"));
                    }
                    _ => {}
                }
                a.pump();
            })
        };
        ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        let tick = {
            let app = app.clone();
            Closure::<dyn FnMut()>::new(move || app.borrow_mut().pump())
        };
        window.set_interval_with_callback_and_timeout_and_arguments_0(
            tick.as_ref().unchecked_ref(),
            10,
        )?;
        tick.forget();
        Ok(())
    }
}
