//! The adapter protocol: how the suite talks to the implementation under test.
//!
//! An adapter is any program that reads one request per line on standard input
//! and writes one response per line on standard output. Values are hex (bytes
//! in wire order; integers as 8 or 4 hex digits, most significant first).
//! Answer `error` when the input must be rejected and `unsupported` for commands
//! the implementation does not provide; those checks are skipped. The commands
//! are listed in `docs/conformance.md` and implemented by [`reference()`].

use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use oss_formats::Level;
use oss_net::VieCipher;
use oss_net::opensec::{self, Direction, IdentityKey, PublicKey, ServerKey, StaticSecret};
use oss_net::relay::Frame;
use oss_proto::checksum::{crc32, map_checksum, settings_checksum, vie_exe_checksum};
use oss_proto::{C2SPacket, C2SPosition, CorePacket, Packet, S2CPacket, S2CWeapon};

use crate::report::{Report, Status};
use crate::vectors::{Case, Expect, hex, unhex};

/// Something that answers adapter requests.
pub trait Adapter {
    /// Sends one request line and returns the response line (trimmed).
    fn call(&mut self, request: &str) -> io::Result<String>;
}

/// The built-in reference implementation (oss-core itself).
#[derive(Debug, Default, Clone, Copy)]
pub struct Reference;

impl Adapter for Reference {
    fn call(&mut self, request: &str) -> io::Result<String> {
        Ok(reference(request))
    }
}

/// An adapter running as a child process.
pub struct Process {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Process {
    /// Starts `program` with `args`.
    pub fn spawn(program: &str, args: &[String]) -> io::Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }
}

impl Adapter for Process {
    fn call(&mut self, request: &str) -> io::Result<String> {
        writeln!(self.stdin, "{request}")?;
        self.stdin.flush()?;
        let mut line = String::new();
        if self.stdout.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "adapter closed its output",
            ));
        }
        Ok(line.trim().to_owned())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs `cases` (filtered to groups starting with `only`, if given) against
/// `adapter`.
pub fn run(adapter: &mut dyn Adapter, cases: &[Case], only: Option<&str>) -> io::Result<Report> {
    let mut report = Report::default();
    for c in cases {
        if only.is_some_and(|p| !c.group.starts_with(p)) {
            continue;
        }
        let got = adapter.call(&c.request)?;
        if got == "unsupported" {
            report.add(c.group, c.id.clone(), Status::Skip, "unsupported");
            continue;
        }
        let ok = match &c.expect {
            Expect::Exact(want) => got.eq_ignore_ascii_case(want),
            Expect::Contains(item) => got.split_whitespace().any(|g| g.eq_ignore_ascii_case(item)),
            Expect::Error => got == "error",
        };
        let detail = || {
            let want = match &c.expect {
                Expect::Exact(w) => w.clone(),
                Expect::Contains(i) => format!("a list containing {i}"),
                Expect::Error => "error".into(),
            };
            format!(
                "request `{}` expected `{}` got `{}`",
                shorten(&c.request),
                shorten(&want),
                shorten(&got)
            )
        };
        if ok {
            report.pass(c.group, c.id.clone());
        } else {
            report.fail(c.group, c.id.clone(), detail());
        }
    }
    Ok(report)
}

fn shorten(s: &str) -> String {
    if s.len() <= 120 {
        s.to_owned()
    } else {
        format!("{}...({} chars)", &s[..100], s.len())
    }
}

/// Serves the reference adapter on standard input/output until EOF.
pub fn serve_stdio() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        writeln!(out, "{}", reference(line?.trim()))?;
        out.flush()?;
    }
    Ok(())
}

fn u32_arg(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 16).ok()
}

fn key32(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

fn dir(s: &str) -> Option<Direction> {
    match s {
        "c2s" => Some(Direction::ClientToServer),
        "s2c" => Some(Direction::ServerToClient),
        _ => None,
    }
}

/// Bit locations of every named setting (from `oss_proto::settings::layout`).
pub fn settings_layout() -> Vec<(String, u32, u32)> {
    oss_proto::settings::layout()
        .into_iter()
        .map(|l| (l.name, l.bit_offset, l.bit_len))
        .collect()
}

/// The reference answer to one request line.
pub fn reference(request: &str) -> String {
    let a: Vec<&str> = request.split_whitespace().collect();
    answer(&a).unwrap_or_else(|| "error".into())
}

fn answer(a: &[&str]) -> Option<String> {
    Some(match a {
        ["hello", ..] => format!("hello oss-core {}", env!("CARGO_PKG_VERSION")),
        ["vie.connect_request", key] => {
            let key = u32_arg(key)?;
            let mut p = vec![0, 1];
            p.extend_from_slice(&key.to_le_bytes());
            p.extend_from_slice(&1u16.to_le_bytes());
            hex(&p)
        }
        ["vie.server_key", key] => format!("{:08x}", oss_net::vie::server_key_for(u32_arg(key)?)),
        ["vie.encrypt", key, data] | ["vie.decrypt", key, data] => {
            let mut d = unhex(data)?;
            if let Some(c) = VieCipher::new(u32_arg(key)?) {
                if a[0] == "vie.encrypt" {
                    c.encrypt(&mut d);
                } else {
                    c.decrypt(&mut d);
                }
            }
            hex(&d)
        }
        ["checksum.exe", key] => format!("{:08x}", vie_exe_checksum(u32_arg(key)?)),
        ["checksum.c2s_position_valid", p] => {
            let p = C2SPosition::decode(&unhex(p)?).ok()?;
            if p.checksum_ok() { "yes" } else { "no" }.into()
        }
        ["checksum.s2c_weapon", p] => {
            // The encoder writes a fresh checksum.
            let b = S2CWeapon::decode(&unhex(p)?).ok()?.to_bytes();
            format!("{:02x}", b[S2CWeapon::CHECKSUM_OFFSET])
        }
        ["checksum.settings", key, p] => {
            format!("{:08x}", settings_checksum(u32_arg(key)?, &unhex(p)?))
        }
        ["checksum.crc32", data] => format!("{:08x}", crc32(&unhex(data)?)),
        ["checksum.map", key, lvl] => {
            let level = Level::parse(&unhex(lvl)?).ok()?;
            let grid = level.server_tile_grid().0;
            format!(
                "{:08x}",
                map_checksum(u32_arg(key)?, |x, y| grid.get(x as u32, y as u32))
            )
        }
        ["settings.locate", name] => {
            let found: Vec<String> = settings_layout()
                .into_iter()
                .filter(|(n, ..)| n == name)
                .map(|(_, o, l)| format!("{o}:{l}"))
                .collect();
            if found.is_empty() {
                return None;
            }
            found.join(" ")
        }
        ["opensec.client_hello", secret, caps, identity @ ..] if identity.len() <= 1 => {
            let s = StaticSecret::from(key32(secret)?);
            let caps = u16::from_str_radix(caps, 16).ok()?;
            let identity = match identity.first() {
                Some(i) => Some(IdentityKey::from_secret(key32(i)?).public()),
                None => None,
            };
            hex(&opensec::client_hello_with_identity(
                PublicKey::from(&s).as_bytes(),
                caps,
                identity.as_ref(),
            ))
        }
        ["opensec.server_hello", eph, stat, caps, client_hello] => {
            let eph = StaticSecret::from(key32(eph)?);
            let stat = match *stat {
                "-" => None,
                s => Some(ServerKey::from_secret(key32(s)?)),
            };
            let caps = u16::from_str_radix(caps, 16).ok()?;
            let (hello, _) =
                opensec::server_respond(&unhex(client_hello)?, &eph, stat.as_ref(), caps)?;
            hex(&hello)
        }
        [
            "opensec.client_keys",
            eph,
            client_hello,
            server_hello,
            identity @ ..,
        ] if identity.len() <= 1 => {
            let eph = StaticSecret::from(key32(eph)?);
            let identity = match identity.first() {
                Some(i) => Some(IdentityKey::from_secret(key32(i)?)),
                None => None,
            };
            let (keys, _) = opensec::client_finish_with_identity(
                &unhex(client_hello)?,
                &eph,
                &unhex(server_hello)?,
                None,
                identity.as_ref(),
            )
            .ok()?;
            format!("{} {}", hex(&keys.c2s), hex(&keys.s2c))
        }
        ["opensec.seal", key, d, counter, plain] => hex(&opensec::seal_record(
            &key32(key)?,
            dir(d)?,
            counter.parse().ok()?,
            &unhex(plain)?,
        )),
        ["opensec.open", key, d, counter, wire] => hex(&opensec::open_record(
            &key32(key)?,
            dir(d)?,
            counter.parse().ok()?,
            &unhex(wire)?,
        )?),
        ["packet.roundtrip", "s2c", p] => hex(&S2CPacket::decode(&unhex(p)?).ok()?.to_bytes()),
        ["packet.roundtrip", "c2s", p] => hex(&C2SPacket::decode(&unhex(p)?).ok()?.to_bytes()),
        ["packet.roundtrip", "core", p] => {
            let b = unhex(p)?;
            hex(&CorePacket::decode(&b).ok()?.to_bytes())
        }
        ["packet.roundtrip", "s2b", p] => {
            hex(&oss_proto::billing::ServerToBiller::decode(&unhex(p)?)
                .ok()
                .filter(|p| !matches!(p, oss_proto::billing::ServerToBiller::Unknown { .. }))?
                .to_bytes())
        }
        ["packet.roundtrip", "b2s", p] => {
            hex(&oss_proto::billing::BillerToServer::decode(&unhex(p)?)
                .ok()
                .filter(|p| !matches!(p, oss_proto::billing::BillerToServer::Unknown { .. }))?
                .to_bytes())
        }
        ["packet.roundtrip", "directory", p] => {
            let u = oss_proto::directory::ZoneUpdate::decode(&unhex(p)?).ok()?;
            let mut out = Vec::new();
            u.encode(&mut out);
            hex(&out)
        }
        ["relay.frame", p] => {
            let b = unhex(p)?;
            let f = Frame::decode(&b).ok()?;
            let mut out = Vec::new();
            f.encode(&mut out).ok()?;
            hex(&out)
        }
        _ => "unsupported".into(),
    })
}
