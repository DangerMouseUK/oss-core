//! `oss-conformance`: run the conformance suite (see `docs/conformance.md`).

use std::net::{ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

use oss_conformance::adapter::{self, Process, Reference};
use oss_conformance::live::{self, BillerOptions, ClientOptions, DirectoryOptions, ServerOptions};
use oss_conformance::{Report, vectors};

const HELP: &str = "\
oss-conformance: check a SubSpace/Continuum protocol implementation

usage:
  oss-conformance vectors [--only PREFIX] [--verbose] [-- ADAPTER [ARGS...]]
      Offline checks from the published vectors. With an adapter command after
      `--`, the suite starts it and talks to it over stdin/stdout (protocol in
      docs/conformance.md); without one it checks oss-core itself.
  oss-conformance adapter
      Serve the reference adapter (oss-core) on stdin/stdout.
  oss-conformance server HOST:PORT [--name N] [--password P] [--arena A] [--timeout S]
      Connect to a running server as a client and check it.
  oss-conformance client [--bind ADDR] [--wait S] [--timeout S]
      Act as a zone on ADDR (default 127.0.0.1:5000) and check the first
      client that connects.
  oss-conformance directory [--bind ADDR] [--zone HOST:PORT] [--wait S] [--repeat]
      Act as a directory server on ADDR (default 0.0.0.0:4991) and check the
      first zone registration that arrives; --zone checks the registered port
      against the zone's real one, --repeat also checks the interval.
  oss-conformance biller [--bind ADDR] [--zone HOST:PORT] [--wait S] [--timeout S]
      Act as an SSC billing server on ADDR (default 0.0.0.0:1850) and check the
      zone that connects; with --zone, also log a player in and out through the
      zone and check the relayed login and logoff.
  oss-conformance list
      List the offline check groups and counts.

Exit status: 0 if nothing failed, 1 if a check failed, 2 on usage or I/O errors.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(report) => {
            print!("{}", report.render(verbose(&args), 50));
            if report.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

fn verbose(args: &[String]) -> bool {
    args.iter()
        .take_while(|a| *a != "--")
        .any(|a| a == "--verbose" || a == "-v")
}

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
    args[..end]
        .windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}

fn secs(args: &[String], name: &str, default: u64) -> Result<Duration, String> {
    match opt(args, name) {
        None => Ok(Duration::from_secs(default)),
        Some(v) => v
            .parse()
            .map(Duration::from_secs)
            .map_err(|e| format!("{name}: {e}")),
    }
}

fn run(args: &[String]) -> Result<Report, String> {
    match args.first().map(String::as_str) {
        Some("vectors") => {
            let cases = vectors::cases();
            let only = opt(args, "--only");
            let report = match args.iter().position(|a| a == "--") {
                Some(i) if i + 1 < args.len() => {
                    let mut p = Process::spawn(&args[i + 1], &args[i + 2..])
                        .map_err(|e| format!("cannot start adapter {}: {e}", args[i + 1]))?;
                    adapter::run(&mut p, &cases, only)
                }
                _ => adapter::run(&mut Reference, &cases, only),
            };
            report.map_err(|e| format!("adapter error: {e}"))
        }
        Some("adapter") => {
            adapter::serve_stdio().map_err(|e| e.to_string())?;
            std::process::exit(0);
        }
        Some("server") => {
            let target = args
                .get(1)
                .filter(|a| !a.starts_with("--"))
                .ok_or("server needs HOST:PORT")?;
            let addr = target
                .to_socket_addrs()
                .map_err(|e| format!("{target}: {e}"))?
                .next()
                .ok_or(format!("{target}: no address"))?;
            let opts = ServerOptions {
                name: opt(args, "--name").map(str::to_owned),
                password: opt(args, "--password").unwrap_or("conformance").to_owned(),
                arena: opt(args, "--arena").map(str::to_owned),
                timeout: secs(args, "--timeout", 5)?,
            };
            live::check_server(addr, &opts).map_err(|e| e.to_string())
        }
        Some("client") => {
            let bind = opt(args, "--bind").unwrap_or("127.0.0.1:5000");
            let sock = UdpSocket::bind(bind).map_err(|e| format!("{bind}: {e}"))?;
            let opts = ClientOptions {
                connect_timeout: secs(args, "--wait", 120)?,
                timeout: secs(args, "--timeout", 10)?,
                ..ClientOptions::default()
            };
            eprintln!(
                "waiting for a client on {} (up to {} s)...",
                sock.local_addr().map_err(|e| e.to_string())?,
                opts.connect_timeout.as_secs()
            );
            live::check_client(sock, &opts).map_err(|e| e.to_string())
        }
        Some("directory") => {
            let bind = opt(args, "--bind").unwrap_or("0.0.0.0:4991");
            let sock = UdpSocket::bind(bind).map_err(|e| format!("{bind}: {e}"))?;
            let opts = DirectoryOptions {
                wait: secs(args, "--wait", 120)?,
                repeat: args.iter().any(|a| a == "--repeat"),
                game_port: match opt(args, "--zone") {
                    Some(z) => Some(
                        z.to_socket_addrs()
                            .map_err(|e| format!("{z}: {e}"))?
                            .next()
                            .ok_or(format!("{z}: no address"))?
                            .port(),
                    ),
                    None => None,
                },
            };
            eprintln!(
                "waiting for a zone registration on {} (up to {} s)...",
                sock.local_addr().map_err(|e| e.to_string())?,
                opts.wait.as_secs()
            );
            live::check_zone_registration(sock, &opts).map_err(|e| e.to_string())
        }
        Some("biller") => {
            let bind = opt(args, "--bind").unwrap_or("0.0.0.0:1850");
            let sock = UdpSocket::bind(bind).map_err(|e| format!("{bind}: {e}"))?;
            let zone = match opt(args, "--zone") {
                Some(z) => Some(
                    z.to_socket_addrs()
                        .map_err(|e| format!("{z}: {e}"))?
                        .next()
                        .ok_or(format!("{z}: no address"))?,
                ),
                None => None,
            };
            let opts = BillerOptions {
                wait: secs(args, "--wait", 120)?,
                timeout: secs(args, "--timeout", 10)?,
                zone,
            };
            eprintln!(
                "waiting for a zone to connect to the biller on {} (up to {} s)...",
                sock.local_addr().map_err(|e| e.to_string())?,
                opts.wait.as_secs()
            );
            live::check_zone_billing(sock, &opts).map_err(|e| e.to_string())
        }
        Some("list") => {
            let mut groups: Vec<(&str, usize)> = Vec::new();
            for c in vectors::cases() {
                match groups.iter_mut().find(|(g, _)| *g == c.group) {
                    Some((_, n)) => *n += 1,
                    None => groups.push((c.group, 1)),
                }
            }
            for (g, n) in groups {
                println!("{g:<28} {n:>6}");
            }
            std::process::exit(0);
        }
        _ => Err(HELP.into()),
    }
}
