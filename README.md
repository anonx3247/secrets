# sx

Conditioned secret access for sandboxed AI agents.

Agents need secrets, but environment variables leak them to the whole agent (and
its LLM context), and a `.env` the agent can read can't be sandboxed away. `sx`
lets programs the agent runs *use* secrets without letting the agent *read*
them, with a human in the loop: a TouchID grant per `.env` file (1 hour) and, by
default, a confirmation of every command.

- **`sxd`** — a secrets oracle outside the sandbox. Reads `.env` files, grants a
  file for 1 hour on first use, confirms each command (unless the file is
  `grant-all`), and releases values. It never executes anything.
- **`sx`** — the in-sandbox client. For `run`, it receives the granted values,
  injects them, and execs the command as **its own** child — so the child
  inherits `sx`'s sandbox and the daemon is never a way out of it. Redacts the
  values from the command's output.

```sh
sxd                                   # run the daemon (outside the sandbox)

# Default: grant the file for 1h on first use, AND confirm every command.
sx run --env .env -- gh pr create     # 1st use: TouchID grants .env + confirms this cmd
sx run --env .env -- gh pr merge      # within the hour: still confirms THIS command

# Opt a file out of per-command confirmation for the hour (off by default):
sx grant-all --env .env               # one prompt, then its commands run unprompted
sx run --env .env -- gh pr merge      # no prompt

sx status                             # granted files + mode + names (never values)
sx clear .env                         # revoke early
```

## Teaching agents to use it

[`SKILL.md`](./SKILL.md) is an Agent-Skills skill that tells a coding agent to
reach for `sx run --env` (and never to read secret values). Install it into the
agents you use:

```sh
sx skill install                 # Claude Code, Codex, and Pi (all three)
sx skill install --claude        # just one; --print for a dry run
sx skill uninstall               # remove it
```

All three implement the same Agent Skills standard, so it's the same `SKILL.md`
in each one's skills directory: `~/.claude/skills/sx/SKILL.md` (Claude Code),
`~/.codex/skills/sx/SKILL.md` (Codex), and `~/.pi/agent/skills/sx/SKILL.md`
(Pi). Restart a running agent session to pick it up.

See [DESIGN.md](./DESIGN.md) for the threat model, the double-gate model, and
known v1 simplifications.
