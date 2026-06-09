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
mod service;
mod state;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
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
    let raw: Vec<String> = std::env::args().skip(1).collect();

    // Service-management subcommands run and exit; they don't start the daemon.
    match raw.first().map(String::as_str) {
        Some("install") => {
            let dry_run = raw.iter().any(|a| a == "--print" || a == "--dry-run");
            return service::install(dry_run).map_err(Into::into);
        }
        Some("uninstall") => return service::uninstall().map_err(Into::into),
        _ => {}
    }

    let mut socket = socket_path();
    let mut gate: Box<dyn ApprovalGate> = default_gate();

    let mut args = raw.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = PathBuf::from(args.next().context("--socket needs a value")?);
            }
            "--no-gate" => gate = Box::new(AllowAllGate),
            "--cli-gate" => gate = Box::new(CliGate),
            "-h" | "--help" => {
                println!(
                    "usage: sxd [--socket PATH] [--cli-gate] [--no-gate]\n       \
                     sxd install [--print]   # register a login auto-start agent (macOS)\n       \
                     sxd uninstall"
                );
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
            Request::GrantAll { env, aws_profiles } => self.grant_all(env, aws_profiles, peer),
            Request::Run {
                env,
                aws_profiles,
                argv,
                grant_all,
            } => self.run(env, aws_profiles, argv, grant_all, peer),
        }
    }

    /// Drop captures. A `path` is resolved the same way `capture` resolves it
    /// (relative to the caller's verified cwd, then canonicalized) so that the
    /// argument matches the canonical key the capture is stored under — without
    /// this, `sx clear .env` would never match and the secret would not revoke.
    fn clear(&self, path: Option<String>, peer: &Peer) -> Response {
        let target = path.map(|p| {
            // AWS source keys (`aws:<profile>`) are synthetic identities, not
            // filesystem paths — match them verbatim, never canonicalize.
            if p.starts_with(AWS_SOURCE_PREFIX) {
                return p;
            }
            match peer.cwd() {
                Ok(cwd) => resolve(&cwd, &p)
                    .map(|r| r.display().to_string())
                    .unwrap_or(p),
                Err(_) => p,
            }
        });
        let n = self.state.lock().unwrap().clear(target.as_deref());
        Response::Ok {
            message: format!("cleared {n} grant(s)"),
        }
    }

    /// Pre-authorize sources in allow-all mode (no command). Prompts once per
    /// source to grant it for the window with the per-command prompt suppressed.
    fn grant_all(&self, env: Vec<String>, aws_profiles: Vec<String>, peer: &Peer) -> Response {
        if env.is_empty() && aws_profiles.is_empty() {
            return Response::Error {
                message: "grant-all requires at least one --env <path> or --aws-profile <profile>"
                    .to_string(),
            };
        }
        let sources = match self.build_sources(&env, &aws_profiles, peer) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        let count = sources.len();
        for src in &sources {
            if let Err(resp) = self.authorize(src, None, true) {
                return resp;
            }
        }
        Response::Ok {
            message: format!("allow-all granted for {count} source(s) (1h)"),
        }
    }

    /// Resolve each source, run both gates, then return the merged values for
    /// the client to inject and exec `argv`.
    fn run(
        &self,
        env: Vec<String>,
        aws_profiles: Vec<String>,
        argv: Vec<String>,
        grant_all: bool,
        peer: &Peer,
    ) -> Response {
        if argv.is_empty() {
            return Response::Error {
                message: "run requires a command".to_string(),
            };
        }
        if env.is_empty() && aws_profiles.is_empty() {
            return Response::Error {
                message: "run requires at least one --env <path> or --aws-profile <profile>"
                    .to_string(),
            };
        }

        let sources = match self.build_sources(&env, &aws_profiles, peer) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

        // Merge the values of every requested source, in order (later sources
        // win), running both gates per source along the way.
        let mut merged: Vec<(String, String)> = Vec::new();
        for src in &sources {
            let values = match self.authorize(src, Some(&argv), grant_all) {
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

    /// Turn the client's `--env` paths and `--aws-profile` names into resolved
    /// [`Source`]s, preserving order (env first, then AWS).
    ///
    /// The caller's verified cwd is only derived when there is at least one
    /// `.env` path to resolve, so an AWS-only request never fails on a
    /// transient `proc_pidinfo` hiccup. AWS profiles are NOT touched by
    /// filesystem resolution — they are keyed under a synthetic `aws:<profile>`.
    fn build_sources(
        &self,
        env: &[String],
        aws_profiles: &[String],
        peer: &Peer,
    ) -> Result<Vec<Source>, Response> {
        let mut sources = Vec::with_capacity(env.len() + aws_profiles.len());
        if !env.is_empty() {
            let cwd = match peer.cwd() {
                Ok(c) => c,
                Err(e) => {
                    return Err(Response::Error {
                        message: format!("cannot determine caller cwd (pid {}): {e}", peer.pid),
                    })
                }
            };
            for path in env {
                let resolved = match resolve(&cwd, path) {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(Response::Error {
                            message: format!("cannot resolve {path}: {e}"),
                        })
                    }
                };
                sources.push(Source::Env {
                    key: resolved.display().to_string(),
                    path: resolved,
                });
            }
        }
        for profile in aws_profiles {
            sources.push(Source::Aws {
                key: format!("{AWS_SOURCE_PREFIX}{profile}"),
                profile: profile.clone(),
            });
        }
        Ok(sources)
    }

    /// The two gates for one already-resolved source.
    ///
    /// * **File grant** — if no live grant exists, prompt a 1h grant and read
    ///   (or mint) its values. `make_allow_all` decides whether the new grant
    ///   is allow-all.
    /// * **Per-command** — when the grant is *not* allow-all and `argv` is
    ///   `Some`, prompt to approve this specific command. `make_allow_all`
    ///   upgrades a live confirm-mode grant to allow-all (prompted) instead.
    ///
    /// `argv == None` means "pre-authorize only" (no command to confirm).
    /// `Err(Response)` carries a denial/error to return verbatim.
    fn authorize(
        &self,
        src: &Source,
        argv: Option<&[String]>,
        make_allow_all: bool,
    ) -> Result<Vec<(String, String)>, Response> {
        let source = src.key();
        let live = self.state.lock().unwrap().live(source);

        // First use of this source → file-grant gate (reads/mints fresh).
        let Some(live) = live else {
            return self.establish_grant(src, argv, make_allow_all);
        };

        // Already allow-all, and not asked to change → no prompt.
        if live.allow_all && !make_allow_all {
            return Ok(live.values);
        }

        // Asked to upgrade a confirm-mode grant to allow-all.
        if make_allow_all {
            if !self.gate.approve(&allow_all_prompt(src)) {
                return Err(Response::Denied {
                    reason: format!("allow-all not approved for {source}"),
                });
            }
            self.state
                .lock()
                .unwrap()
                .set_allow_all(source, Duration::from_secs(GRANT_TTL_SECS));
            return Ok(live.values);
        }

        // Confirm-mode grant + a command → per-command gate.
        let argv = argv.expect("confirm-mode path always has a command");
        if !self.gate.approve(&per_command_prompt(src, argv)) {
            return Err(Response::Denied {
                reason: "command not approved".to_string(),
            });
        }
        // Re-resolve after approval: the grant may have expired at the prompt.
        match self.state.lock().unwrap().live(source) {
            Some(g) => Ok(g.values),
            None => Err(Response::Denied {
                reason: format!("grant for {source} expired during approval"),
            }),
        }
    }

    /// First-use grant: prompt, read/mint the source's values, store them.
    fn establish_grant(
        &self,
        src: &Source,
        argv: Option<&[String]>,
        allow_all: bool,
    ) -> Result<Vec<(String, String)>, Response> {
        let prompt = if allow_all {
            allow_all_prompt(src)
        } else {
            first_run_prompt(src, argv)
        };
        if !self.gate.approve(&prompt) {
            return Err(Response::Denied {
                reason: format!("grant not approved for {}", src.key()),
            });
        }

        // Read/mint values only AFTER approval. On failure return the carried
        // Response verbatim so any CLI stderr never enters a successful grant.
        let values = src.values()?;

        self.state.lock().unwrap().add(
            src.key().to_string(),
            values.clone(),
            Duration::from_secs(GRANT_TTL_SECS),
            allow_all,
        );

        let mut out: Vec<(String, String)> = values.into_iter().collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

/// Synthetic source-key prefix for AWS-profile grants (`aws:<profile>`). These
/// keys are never filesystem paths and must bypass `resolve`/`canonicalize`.
const AWS_SOURCE_PREFIX: &str = "aws:";

/// A resolved secret source: a canonical `.env` file path, or a named AWS
/// profile. This is the one place that differs between backends — the State
/// key it is stored under, the subject shown at the human gate, and how its
/// values are produced ("minted"). Everything else (TTL, grant/allow-all
/// machinery, status, redaction) is identical across sources.
enum Source {
    /// A `.env` file: `key` is its canonical path (also the display identity).
    Env { key: String, path: PathBuf },
    /// An AWS profile: `key` is `aws:<profile>`, `profile` the bare name.
    Aws { key: String, profile: String },
}

impl Source {
    /// The State key this source is stored under (also shown by `status`).
    fn key(&self) -> &str {
        match self {
            Source::Env { key, .. } | Source::Aws { key, .. } => key,
        }
    }

    /// Subject phrase for the grant / allow-all prompts ("...access to X").
    fn subject(&self) -> String {
        match self {
            Source::Env { path, .. } => format!("secrets in:\n  {}", path.display()),
            Source::Aws { profile, .. } => format!("AWS credentials for profile:\n  {profile}"),
        }
    }

    /// Subject phrase for the per-command prompt ("...with X").
    fn subject_from(&self) -> String {
        match self {
            Source::Env { path, .. } => format!("secrets from:\n  {}", path.display()),
            Source::Aws { profile, .. } => format!("AWS credentials for profile:\n  {profile}"),
        }
    }

    /// Produce this source's name→value map, or a `Response` to return verbatim
    /// on failure (so error detail / CLI stderr never folds into a grant).
    fn values(&self) -> Result<HashMap<String, String>, Response> {
        match self {
            Source::Env { path, key } => parse_env(path).map_err(|e| Response::Error {
                message: format!("reading {key}: {e:#}"),
            }),
            Source::Aws { profile, .. } => mint_aws(profile),
        }
    }
}

fn first_run_prompt(src: &Source, argv: Option<&[String]>) -> String {
    let mut p = format!(
        "Grant access to {}\nfor {} minutes.",
        src.subject(),
        GRANT_TTL_SECS / 60
    );
    if let Some(argv) = argv {
        p.push_str(&format!("\nThis command will run:\n  {}", argv.join(" ")));
    }
    p
}

fn per_command_prompt(src: &Source, argv: &[String]) -> String {
    format!(
        "Run command:\n  {}\nwith {}",
        argv.join(" "),
        src.subject_from()
    )
}

fn allow_all_prompt(src: &Source) -> String {
    format!(
        "Allow ALL commands to use {}\nfor {} minutes, without confirming each one.",
        src.subject(),
        GRANT_TTL_SECS / 60
    )
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

/// Mint temporary AWS credentials for `profile` by shelling out to the AWS CLI.
///
/// Runs `aws configure export-credentials --profile <profile> --format
/// env-no-export`, which resolves SSO, assume-role, and static profiles
/// uniformly and prints `KEY=VALUE` lines (`AWS_ACCESS_KEY_ID`,
/// `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and usually
/// `AWS_CREDENTIAL_EXPIRATION` / `AWS_REGION`).
///
/// We do NOT add an AWS SDK dependency: the CLI is the source of truth for the
/// user's profile config and credential providers. On any failure (missing
/// CLI, non-zero exit) this returns a `Response` carrying the CLI's stderr so
/// the caller surfaces it as a denial/error — the stderr is NEVER folded into a
/// successful grant.
fn mint_aws(profile: &str) -> Result<HashMap<String, String>, Response> {
    let output = match Command::new("aws")
        .args([
            "configure",
            "export-credentials",
            "--profile",
            profile,
            "--format",
            "env-no-export",
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Err(Response::Error {
                message: format!(
                    "cannot run `aws` to mint credentials for profile {profile}: {e} \
                     (is the AWS CLI installed and on PATH?)"
                ),
            })
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Response::Denied {
            reason: format!(
                "aws could not export credentials for profile {profile}: {}",
                stderr.trim()
            ),
        });
    }

    Ok(parse_env_no_export(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse the `KEY=VALUE` lines printed by
/// `aws configure export-credentials --format env-no-export` into a map.
///
/// Each non-empty line is `NAME=VALUE`; values are taken verbatim (this AWS
/// format emits no quoting or escaping). Blank lines are ignored, and a line
/// without `=` is skipped defensively rather than panicking.
fn parse_env_no_export(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.to_string());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_no_export_lines() {
        let out = "AWS_ACCESS_KEY_ID=AKIA123\n\
                   AWS_SECRET_ACCESS_KEY=secret/with+slashes\n\
                   AWS_SESSION_TOKEN=tok==\n\
                   AWS_CREDENTIAL_EXPIRATION=2026-01-01T00:00:00Z\n";
        let map = parse_env_no_export(out);
        assert_eq!(map["AWS_ACCESS_KEY_ID"], "AKIA123");
        assert_eq!(map["AWS_SECRET_ACCESS_KEY"], "secret/with+slashes");
        // A value containing `=` is preserved after the first split.
        assert_eq!(map["AWS_SESSION_TOKEN"], "tok==");
        assert_eq!(map["AWS_CREDENTIAL_EXPIRATION"], "2026-01-01T00:00:00Z");
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn skips_blank_and_malformed_lines() {
        let map = parse_env_no_export("\n  \nNOEQUALS\nA=1\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map["A"], "1");
    }

    #[test]
    fn aws_source_uses_profile_in_prompts_and_key() {
        let src = Source::Aws {
            key: format!("{AWS_SOURCE_PREFIX}prod"),
            profile: "prod".to_string(),
        };
        assert_eq!(src.key(), "aws:prod");
        let first = first_run_prompt(&src, Some(&["cmd".to_string()]));
        assert!(first.contains("AWS credentials for profile:\n  prod"));
        assert!(first.contains("This command will run:\n  cmd"));
        assert!(allow_all_prompt(&src).contains("AWS credentials for profile:\n  prod"));
        assert!(per_command_prompt(&src, &["cmd".to_string()])
            .contains("with AWS credentials for profile:\n  prod"));
    }

    #[test]
    fn env_source_keeps_existing_prompt_wording() {
        let src = Source::Env {
            key: "/tmp/.env".to_string(),
            path: PathBuf::from("/tmp/.env"),
        };
        assert_eq!(src.key(), "/tmp/.env");
        assert!(first_run_prompt(&src, None).contains("secrets in:\n  /tmp/.env"));
        assert!(per_command_prompt(&src, &["x".to_string()])
            .contains("with secrets from:\n  /tmp/.env"));
    }
}
