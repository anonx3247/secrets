---
name: sx
description: Run commands that need secrets (API keys, tokens, credentials) from a .env file without reading the secret values. Use whenever a shell command needs a credential that is not already in the environment and lives in a .env file — run the command through `sx run --env <file> -- <command>` instead of reading the file, exporting/sourcing variables, or echoing them.
---

# sx — use secrets without reading them

`sx` runs a command with the secrets from a `.env` file injected into it, while
keeping the secret **values** out of your context. A trusted background daemon
holds the values and injects them into the command's environment; you only ever
see redacted output (`‹redacted›`). You cannot read the values, and you don't
need to.

## When to use this

Reach for `sx` whenever a command needs a secret that isn't already in the
environment — an API token, key, password, or connection string — and that
secret lives in a `.env` file (e.g. `GITHUB_TOKEN`, `OPENAI_API_KEY`,
`DATABASE_URL`, `STRIPE_SECRET_KEY`).

## How

Run the real command through `sx run`, naming the file with `--env`:

```sh
sx run --env .env -- gh pr create --title "..."
sx run --env .env -- curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
sx run --env .env -- npm publish
```

- `--env <path>` is required and repeatable; **all** of the file's variables are
  injected into the command. The variables are real inside the command — refer
  to them normally (`$OPENAI_API_KEY`), they just come back redacted in output.
- The first use of a file prompts the **user** (TouchID) to grant it for an
  hour; by default the user also confirms **each command**. These prompts go to
  the human, not to you.
- See what's available without seeing values: `sx status` (lists files and
  variable names only).

## Rules — important

- **Never try to read a secret value.** Do not `cat` the `.env`, run `printenv`,
  `echo $TOKEN`, or pipe a secret through a command whose only purpose is to
  print it — the value returns as `‹redacted›`, so it only wastes a turn. To
  *use* a secret, wrap the real command in `sx run --env … --`.
- **Always go through `sx run`.** Don't `export` the values or `source` the
  `.env` — a sandbox may block reading the file directly anyway.
- If `sx run` prints `denied:`, the user declined the prompt — **stop and ask**,
  don't retry in a loop.
- Per-command confirmation is the default. If the user is doing many `sx run`
  calls and wants to skip the prompts, they (not you) can run
  `sx grant-all --env <file>` once to allow that file for an hour — suggest it,
  but don't assume it, since it lowers their security.

## Quick reference

| Goal | Command |
|------|---------|
| Run a command with secrets | `sx run --env .env -- <cmd>` |
| Use several files at once | `sx run --env a.env --env b.env -- <cmd>` |
| See available names (no values) | `sx status` |
| (user only) allow a file without per-command prompts | `sx grant-all --env .env` |
| (user only) revoke a file early | `sx clear .env` |
