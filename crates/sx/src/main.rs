//! `sx` — the in-sandbox client.
//!
//! `sx` runs *inside* the agent's sandbox. For `run`, it asks the daemon for
//! the named secrets (the daemon gates that on the user), receives the values,
//! injects them, and execs the command as its own subprocess — so the child
//! inherits this process's sandbox confinement and the daemon never executes
//! anything. `sx` is therefore the single point that briefly holds plaintext
//! inside the sandbox; it is trusted (and, in a follow-up, code-sign-attested
//! by the daemon) to use the values only to launch the requested command and
//! to redact them from that command's output.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sx_proto::{socket_path, Request, Response};

#[derive(Parser)]
#[command(
    name = "sx",
    about = "Conditioned secret access for sandboxed agents",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Drop granted .env files — a single source path, or all of them.
    Clear {
        /// Source path to clear; omit to clear everything.
        path: Option<String>,
    },
    /// Show active grants and the secret names they expose (never values).
    Status,
    /// Alias for `status`, framed as "what secrets can I use right now".
    List,
    /// Grant a .env file for 1h AND allow all its commands without per-command
    /// prompts. Runs nothing — use this to opt a file out of confirmation.
    ///
    /// Example: sx grant-all --env .env
    GrantAll {
        /// Path to a .env file to allow-all (repeatable, required).
        #[arg(long = "env", required = true)]
        env: Vec<String>,
    },
    /// Run a command with the secrets from one or more .env files injected.
    ///
    /// The first use of a given .env prompts for a 1-hour grant; by default
    /// every command is then confirmed individually. Pass --grant-all to opt
    /// the file(s) out of per-command confirmation for the window. The path
    /// must be given each call.
    ///
    /// Example: sx run --env .env -- gh pr create
    Run {
        /// Path to a .env file whose secrets to inject (repeatable, required).
        #[arg(long = "env", required = true)]
        env: Vec<String>,
        /// Skip per-command confirmation for these file(s) for the grant window.
        #[arg(long = "grant-all")]
        grant_all: bool,
        /// The command and its arguments, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sx: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    // `run` is special: the daemon returns the secret values and *we* execute,
    // so the child stays inside our sandbox. Everything else is a simple
    // request/response we just render.
    //
    // Note: we deliberately do NOT send our cwd. The daemon derives the caller's
    // working directory from the verified peer pid to resolve the --env paths,
    // so a compromised client cannot fake where the files live.
    match cli.command {
        Cmd::Run {
            env,
            grant_all,
            argv,
        } => exec_with_secrets(env, argv, grant_all),
        Cmd::GrantAll { env } => Ok(render(send(&Request::GrantAll { env })?)),
        Cmd::Clear { path } => Ok(render(send(&Request::Clear { path })?)),
        Cmd::Status | Cmd::List => Ok(render(send(&Request::Status)?)),
    }
}

/// Ask the daemon (gated) for the secrets in `env`, then inject and exec `argv`
/// as our own child, redacting the secret values from its output.
fn exec_with_secrets(env: Vec<String>, argv: Vec<String>, grant_all: bool) -> Result<ExitCode> {
    let response = send(&Request::Run {
        env,
        argv: argv.clone(),
        grant_all,
    })?;

    let granted = match response {
        Response::Granted { secrets } => secrets,
        other => return Ok(render(other)),
    };

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (name, value) in &granted {
        cmd.env(name, value);
    }
    // Inherit stdin so commands that read input (pipes, prompts) work; capture
    // stdout/stderr so we can redact the secret values out of them before they
    // reach our own stdout (which the agent sees). `wait_with_output` drains
    // both pipes concurrently, avoiding the classic pipe-buffer deadlock.
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd
        .spawn()
        .with_context(|| format!("running {}", argv[0]))?
        .wait_with_output()
        .with_context(|| format!("waiting for {}", argv[0]))?;

    // Redact the injected values from whatever the command emitted before it
    // reaches our stdout/stderr (which the agent sees).
    let values: Vec<&str> = granted.iter().map(|(_, v)| v.as_str()).collect();
    print!("{}", redact(String::from_utf8_lossy(&output.stdout), &values));
    eprint!("{}", redact(String::from_utf8_lossy(&output.stderr), &values));

    Ok(ExitCode::from(
        u8::try_from(output.status.code().unwrap_or(1)).unwrap_or(1),
    ))
}

/// Replace every (non-empty) secret value in `text` with a placeholder.
fn redact(text: std::borrow::Cow<'_, str>, values: &[&str]) -> String {
    let mut text = text.into_owned();
    for v in values {
        if v.is_empty() {
            continue;
        }
        text = text.replace(v, "‹redacted›");
    }
    text
}

/// Send one request and read one response over the daemon socket.
fn send(request: &Request) -> Result<Response> {
    let path = socket_path();
    let stream = UnixStream::connect(&path).with_context(|| {
        format!(
            "cannot reach daemon at {} (is sxd running?)",
            path.display()
        )
    })?;

    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    (&stream).write_all(&line)?;

    let mut reader = BufReader::new(&stream);
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    let response = serde_json::from_str::<Response>(buf.trim())
        .with_context(|| format!("bad response from daemon: {buf:?}"))?;
    Ok(response)
}

/// Print a response and map it to a process exit code.
fn render(response: Response) -> ExitCode {
    match response {
        Response::Ok { message } => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Response::Status { captures } => {
            if captures.is_empty() {
                println!("no active grants");
            } else {
                for c in captures {
                    let mode = if c.allow_all {
                        " [allow-all]"
                    } else {
                        " [confirm each command]"
                    };
                    println!(
                        "{} (expires in {}m){mode}",
                        c.source,
                        c.expires_in_secs / 60
                    );
                    for n in c.names {
                        println!("  {n}");
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Response::Granted { .. } => {
            // Handled by exec_with_secrets; reaching render means a logic error.
            eprintln!("error: unexpected grant outside of run");
            ExitCode::FAILURE
        }
        Response::Denied { reason } => {
            eprintln!("denied: {reason}");
            ExitCode::FAILURE
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
