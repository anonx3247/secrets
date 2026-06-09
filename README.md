# sx

Conditioned secret access for sandboxed AI agents.

Agents need secrets, but environment variables leak them to the whole agent (and
its LLM context), and a `.env` the agent can read can't be sandboxed away. `sx`
lets programs the agent runs *use* secrets without letting the agent *read*
them, with a human in the loop at capture and at each use.

- **`sxd`** — a secrets oracle outside the sandbox. Reads `.env` files, grants
  access on first use (TouchID, 1 hour), caches the grant, and releases values.
  It never executes anything.
- **`sx`** — the in-sandbox client. For `run`, it receives the granted values,
  injects them, and execs the command as **its own** child — so the child
  inherits `sx`'s sandbox and the daemon is never a way out of it. Redacts the
  values from the command's output.

```sh
sxd                                   # run the daemon (outside the sandbox)
sx run --env .env -- gh pr create     # first use: TouchID grants .env for 1h
sx run --env .env -- gh pr merge      # within the hour: no prompt
sx status                             # see granted files + names (never values)
sx clear .env                         # revoke early
```

See [DESIGN.md](./DESIGN.md) for the threat model, the double-gate model, and
known v1 simplifications.
