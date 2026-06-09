//! `sxd` — the secrets daemon.
//!
//! Runs *outside* the agent's sandbox. It is the only component that reads
//! secret material: it captures `.env` files on demand (TouchID-gated),
//! holds the values in memory under a TTL, and injects them into child
//! processes it spawns on the client's behalf — gating each use and redacting
//! the values out of the child's output before returning it.
//!
//! The caller is authenticated via socket peer credentials: only the owning
//! uid may connect, and the `.env` path / child cwd are resolved against the
//! caller's *verified* working directory (derived from its pid), never a field
//! the client supplies.
//!
//! v1 simplifications (see DESIGN.md):
//!   * the spawned child is NOT yet re-sandboxed — it inherits the daemon's
//!     (unsandboxed) context. Production must re-apply the agent's sandbox to
//!     the child so `run` is not an escape hatch.

mod gate;
mod peer;
mod state;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use sx_proto::{socket_path, Request, Response, GRANT_TTL_SECS};

use gate::{AllowAllGate, ApprovalGate, CliGate};
use peer::Peer;
use state::State;

struct Daemon {
    state: Mutex<State>,
    gate: Box<dyn ApprovalGate>,
}

fn main() -> Result<()> {
    let mut socket = socket_path();
    let mut gate: Box<dyn ApprovalGate> = default_gate();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = PathBuf::from(args.next().context("--socket needs a value")?);
            }
            "--no-gate" => gate = Box::new(AllowAllGate),
            "--cli-gate" => gate = Box::new(CliGate),
            "-h" | "--help" => {
                println!("usage: sxd [--socket PATH] [--cli-gate] [--no-gate]");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket dir {}", parent.display()))?;
    }
    // Clear any stale socket from a previous run.
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("binding socket {}", socket.display()))?;

    eprintln!("sxd listening on {}", socket.display());

    let daemon = Daemon {
        state: Mutex::new(State::default()),
        gate,
    };

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = daemon.handle(stream) {
                    eprintln!("sxd: connection error: {e:#}");
                }
            }
            Err(e) => eprintln!("sxd: accept error: {e}"),
        }
    }

    Ok(())
}

/// The gate used unless overridden by a flag: TouchID on macOS (falling back
/// to a terminal prompt when biometrics/passcode can't be evaluated), and a
/// terminal prompt elsewhere.
#[cfg(target_os = "macos")]
fn default_gate() -> Box<dyn ApprovalGate> {
    Box::new(gate::TouchIdGate::new(Box::new(CliGate)))
}

#[cfg(not(target_os = "macos"))]
fn default_gate() -> Box<dyn ApprovalGate> {
    Box::new(CliGate)
}

impl Daemon {
    /// Authenticate the peer, read one request, dispatch it, write one response.
    fn handle(&self, stream: UnixStream) -> Result<()> {
        let response = self.authenticate_and_dispatch(&stream);

        let mut out = stream;
        let mut buf = serde_json::to_vec(&response)?;
        buf.push(b'\n');
        out.write_all(&buf)?;
        out.flush()?;
        Ok(())
    }

    /// Verify the caller, then read and dispatch the request.
    /// Every failure path returns a `Response` so the client always hears back.
    ///
    /// The caller's cwd is derived lazily by the handlers that need it (only
    /// `capture`, and `clear` when given a path), not here — a transient
    /// `proc_pidinfo` failure must not break `status`/`clear`/`run`.
    fn authenticate_and_dispatch(&self, stream: &UnixStream) -> Response {
        let peer = match Peer::from_stream(stream) {
            Ok(p) => p,
            Err(e) => {
                return Response::Error {
                    message: format!("cannot read peer credentials: {e}"),
                }
            }
        };

        // Only the owning user may reach their own secrets.
        if peer.uid != peer::own_uid() {
            return Response::Denied {
                reason: format!("connection from uid {} refused", peer.uid),
            };
        }

        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                return Response::Error {
                    message: format!("socket error: {e}"),
                }
            }
        });
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                return Response::Error {
                    message: "client closed without sending a request".to_string(),
                }
            }
            Ok(_) => {}
            Err(e) => {
                return Response::Error {
                    message: format!("read error: {e}"),
                }
            }
        }

        match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => self.dispatch(req, &peer),
            Err(e) => Response::Error {
                message: format!("malformed request: {e}"),
            },
        }
    }

    fn dispatch(&self, req: Request, peer: &Peer) -> Response {
        match req {
            Request::Clear { path } => self.clear(path, peer),
            Request::Status => Response::Status {
                captures: self.state.lock().unwrap().info(),
            },
            Request::Run { env, argv } => self.run(env, argv, peer),
        }
    }

    /// Drop captures. A `path` is resolved the same way `capture` resolves it
    /// (relative to the caller's verified cwd, then canonicalized) so that the
    /// argument matches the canonical key the capture is stored under — without
    /// this, `sx clear .env` would never match and the secret would not revoke.
    fn clear(&self, path: Option<String>, peer: &Peer) -> Response {
        let target = path.map(|p| match peer.cwd() {
            Ok(cwd) => resolve(&cwd, &p)
                .map(|r| r.display().to_string())
                .unwrap_or(p),
            Err(_) => p,
        });
        let n = self.state.lock().unwrap().clear(target.as_deref());
        Response::Ok {
            message: format!("cleared {n} grant(s)"),
        }
    }

    /// Resolve each `.env`, granting (TouchID, 1h) any not already live, then
    /// return the merged values for the client to inject and exec `argv`.
    ///
    /// The grant for a given file is prompted only on its first use within the
    /// window; later runs reuse the cached values without prompting. The daemon
    /// never spawns `argv` — it only shows it at the grant prompt so the user
    /// knows what the access is for. Execution happens entirely in the
    /// in-sandbox client.
    fn run(&self, env: Vec<String>, argv: Vec<String>, peer: &Peer) -> Response {
        if argv.is_empty() {
            return Response::Error {
                message: "run requires a command".to_string(),
            };
        }
        if env.is_empty() {
            return Response::Error {
                message: "run requires at least one --env <path>".to_string(),
            };
        }

        let cwd = match peer.cwd() {
            Ok(c) => c,
            Err(e) => {
                return Response::Error {
                    message: format!("cannot determine caller cwd (pid {}): {e}", peer.pid),
                }
            }
        };

        // Merge the values of every requested file, in order (later files win),
        // granting first-seen files along the way.
        let mut merged: Vec<(String, String)> = Vec::new();
        for path in &env {
            let resolved = match resolve(&cwd, path) {
                Ok(p) => p,
                Err(e) => {
                    return Response::Error {
                        message: format!("cannot resolve {path}: {e}"),
                    }
                }
            };
            let source = resolved.display().to_string();

            let values = match self.grant(&source, &resolved, &argv) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            for (k, v) in values {
                merged.retain(|(ek, _)| ek != &k);
                merged.push((k, v));
            }
        }

        Response::Granted { secrets: merged }
    }

    /// Return the values for one already-resolved `.env`, prompting a 1h grant
    /// on first use. `Err(Response)` carries a denial/error to return verbatim.
    fn grant(
        &self,
        source: &str,
        resolved: &Path,
        argv: &[String],
    ) -> Result<Vec<(String, String)>, Response> {
        // Already granted and still live → no prompt.
        if let Some(values) = self.state.lock().unwrap().live_values(source) {
            return Ok(values);
        }

        let prompt = format!(
            "Grant access to secrets in:\n  {}\nfor {} minutes. First use is to run:\n  {}",
            resolved.display(),
            GRANT_TTL_SECS / 60,
            argv.join(" ")
        );
        if !self.gate.approve(&prompt) {
            return Err(Response::Denied {
                reason: format!("grant not approved for {source}"),
            });
        }

        let values = match parse_env(resolved) {
            Ok(v) => v,
            Err(e) => {
                return Err(Response::Error {
                    message: format!("reading {source}: {e:#}"),
                })
            }
        };

        self.state.lock().unwrap().add(
            source.to_string(),
            values.clone(),
            Duration::from_secs(GRANT_TTL_SECS),
        );

        let mut out: Vec<(String, String)> = values.into_iter().collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

/// Resolve `path` relative to `cwd` and canonicalize it (file must exist).
fn resolve(cwd: &Path, path: &str) -> std::io::Result<PathBuf> {
    let p = Path::new(path);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    };
    joined.canonicalize()
}

/// Parse a `.env` file into name→value pairs.
fn parse_env(path: &Path) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in dotenvy::from_path_iter(path)? {
        let (k, v) = item?;
        map.insert(k, v);
    }
    Ok(map)
}
