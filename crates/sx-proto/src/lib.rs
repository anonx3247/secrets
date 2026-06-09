//! Wire protocol shared between the `sx` client and the `sxd` daemon.
//!
//! Transport is newline-delimited JSON over a unix domain socket: the client
//! writes exactly one [`Request`] followed by `\n`, the daemon replies with
//! exactly one [`Response`] followed by `\n`.
//!
//! The client is the *in-sandbox* half and is deliberately incapable of
//! reading secret material: it only ever passes paths, names, and argv. The
//! daemon is the *out-of-sandbox* half that actually touches secrets.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Environment variable that overrides the default socket path.
pub const SOCKET_ENV: &str = "SX_SOCKET";

/// Lifetime of a grant: how long a `.env` stays usable after its first run
/// before the next run re-prompts. One hour.
pub const GRANT_TTL_SECS: u64 = 3600;

/// Resolve the unix socket path both halves agree on.
///
/// Honors `$SX_SOCKET`, otherwise falls back to `$HOME/.sx/sxd.sock`.
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var(SOCKET_ENV) {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".sx").join("sxd.sock")
}

/// A request from the client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Drop granted sources — a single source (an `.env` path or an
    /// `aws:<profile>` key), or all of them when `path` is `None`.
    Clear { path: Option<String> },

    /// Report active grants and the secret names they expose (never values).
    Status,

    /// Pre-authorize one or more secret sources in *allow-all* mode: grant the
    /// source for an hour AND suppress the per-command prompt for that window.
    /// Runs no command — `sx grant-all --env <path> --aws-profile <name>`.
    ///
    /// Sources are either `.env` file paths (`env`) or named AWS profiles
    /// (`aws_profiles`); both kinds are gated and TTL'd identically.
    GrantAll {
        env: Vec<String>,
        /// AWS profile names to mint temporary credentials from.
        #[serde(default)]
        aws_profiles: Vec<String>,
    },

    /// Request the secrets from one or more sources in order to run `argv`.
    ///
    /// The daemon does NOT execute anything. Sources come in two flavors:
    ///
    /// * `env` — `.env` file paths, resolved against the caller's *verified*
    ///   cwd (derived from the peer pid, not sent here) and canonicalized.
    /// * `aws_profiles` — named AWS profiles; the daemon mints temporary
    ///   credentials by shelling out to `aws configure export-credentials` and
    ///   injects the resulting `AWS_*` env vars. Keyed under `aws:<profile>`,
    ///   never touched by filesystem resolution.
    ///
    /// Two independent gates apply to every source:
    ///
    /// * **file grant** — on first use of a source, a 1h TouchID grant reads
    ///   (or mints) its values into memory; later runs reuse them.
    /// * **per-command** — by default *every* run prompts to approve this
    ///   specific command. A source in allow-all mode (via [`Request::GrantAll`]
    ///   or `grant_all` here) skips this prompt for its window.
    ///
    /// It returns the merged values via [`Response::Granted`]; the client (`sx`)
    /// injects them and execs `argv` itself. `argv` is sent so the daemon can
    /// show it at the per-command prompt; the daemon does not run it.
    Run {
        env: Vec<String>,
        /// AWS profile names to mint temporary credentials from.
        #[serde(default)]
        aws_profiles: Vec<String>,
        argv: Vec<String>,
        /// Upgrade the sources used here to allow-all for the rest of their grant.
        grant_all: bool,
    },
}

/// A response from the daemon to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Generic success with a human-readable message.
    Ok { message: String },

    /// Current daemon state.
    Status { captures: Vec<CaptureInfo> },

    /// The per-use gate approved: here are the requested secret values for the
    /// client to inject into the child it is about to exec. This is the only
    /// message that carries plaintext, and only to an (eventually attested)
    /// in-sandbox `sx`. `secrets` preserves request order as (name, value).
    Granted { secrets: Vec<(String, String)> },

    /// A gate (capture or per-use) refused, or a precondition failed.
    Denied { reason: String },

    /// The daemon hit an internal error handling the request.
    Error { message: String },
}

/// Summary of one active grant, safe to show the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureInfo {
    /// Source identity: a canonical `.env` path, or `aws:<profile>` for an
    /// AWS-profile grant.
    pub source: String,
    pub names: Vec<String>,
    pub expires_in_secs: u64,
    /// True when this source is in allow-all mode (no per-command prompt).
    pub allow_all: bool,
}
