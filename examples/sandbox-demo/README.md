# sandbox demo

Prove the core property end to end: a process inside a sandbox can **use** a
secret through `sx run` but cannot **read** it.

`sx-sandbox.sb` is a macOS Seatbelt profile that stands in for "the agent's
sandbox" — it allows everything **except** reading `.env` files. (A real
deployment would be deny-by-default and also restrict network egress; this
permissive form keeps the demo focused on read-vs-use.)

## Prerequisites

- `sxd` running and `sx` on your `PATH`. From the repo root:
  ```sh
  ./install.sh         # builds, installs sx + sxd, auto-starts sxd at login
  ```
- The skill installed (optional, for the agent test below):
  ```sh
  sx skill install
  ```

## Quick test (shell)

```sh
examples/sandbox-demo/try.sh
```

It creates a throwaway project with a secret `.env`, then, **inside the
sandbox**:

1. `cat .env` → **fails** (`Operation not permitted`).
2. `printenv API_KEY` → **empty** (the secret isn't in the agent's environment).
3. `sx run --env .env -- …` → **approve** the TouchID prompt; the command gets
   the real value, but the output you see is `‹redacted›`.
4. a suspicious command → **deny** the TouchID prompt; nothing is released.

## Run a real agent in the sandbox

Install the skill, then launch your agent under the same profile, from a project
that has a `.env`:

```sh
cd /path/to/project          # contains a .env with e.g. GITHUB_TOKEN
sandbox-exec -f /ABS/PATH/sx-sandbox.sb codex     # or: pi, or your agent
```

Then give it a task that needs the secret, e.g.:

> Use the GITHUB_TOKEN in .env to list my open PRs with `gh`.

With the skill installed, the agent runs `sx run --env .env -- gh pr list`
(prompting you for approval) instead of reading the file — and if it *tries* to
`cat .env`, the sandbox blocks it.

## What this demonstrates / what it doesn't

- ✅ The secret value never enters the agent's process, context, or environment.
- ✅ The agent can only obtain access through `sx`, which is human-gated.
- ⚠️ Redaction scrubs only verbatim echoes; a transformed or network-exfiltrated
  value can still leak once a command is approved. Stopping that is the job of
  the per-command prompt (you approve each command) and, in production, a
  network-egress allowlist on the sandbox.
