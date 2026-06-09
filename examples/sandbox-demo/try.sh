#!/usr/bin/env bash
# End-to-end demo for sx: prove that a process inside a sandbox can USE a secret
# via `sx run` but cannot READ it.
#
# Prerequisites:
#   - sxd running (see `sxd install`) and `sx` on PATH (~/.cargo/bin)
#   - macOS (uses sandbox-exec / Seatbelt)
#
# Steps 4 and 5 trigger TouchID prompts from sxd. APPROVE step 4, DENY step 5.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$HERE/sx-sandbox.sb"
SX="$(command -v sx || echo "$HOME/.cargo/bin/sx")"

PROJ="$(mktemp -d)"
trap 'rm -rf "$PROJ"' EXIT
printf 'API_KEY=sk-DEMO-SECRET-aabbccddeeff\n' >"$PROJ/.env"

box() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
sandboxed() { (cd "$PROJ" && sandbox-exec -f "$PROFILE" "$@"); }

echo "Scratch project: $PROJ"
echo "Secret on disk:  $(cat "$PROJ"/.env)"

box "0) sxd reachable?"
"$SX" status || {
  echo "sxd not running. Run 'sxd install' (or start 'sxd') first."
  exit 1
}

box "1) read the .env directly from inside the sandbox  ->  must FAIL"
sandboxed /bin/cat .env

box "2) is the secret in the sandbox's ambient environment?  ->  must be EMPTY"
if sandboxed /usr/bin/printenv API_KEY; then echo "!! LEAK"; else echo "(not set — good)"; fi

box "3) USE the secret via sx  ->  APPROVE the TouchID prompt"
echo "   the command receives the real value; what returns to us is redacted:"
sandboxed "$SX" run --env .env -- /bin/sh -c \
  'echo "command got API_KEY (length ${#API_KEY}): $API_KEY"'

box "4) a suspicious command  ->  DENY the TouchID prompt"
echo "   you see the exact command before approving; deny it and no value is released:"
sandboxed "$SX" run --env .env -- /bin/sh -c \
  'echo "exfiltrating $API_KEY to evil.example.com"'

box "summary"
cat <<'EOF'
 step 1 blocked     -> the agent cannot read the .env
 step 2 empty       -> the secret is not in the agent's environment
 step 3 redacted    -> the command USED the secret; we only saw '‹redacted›'
 step 4 denied      -> the human gate stopped an unapproved use

What this does NOT show (by design): redaction only scrubs verbatim echoes.
A command that transforms the value (base64, rev, encrypt) or sends it over the
network can still leak it once approved — that is what the per-command prompt
(you saw it) and, in a real deployment, network-egress restriction are for.
EOF
