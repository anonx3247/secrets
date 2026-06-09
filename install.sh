#!/usr/bin/env bash
# Build, install the sx + sxd binaries, and register sxd to auto-start at login.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Installing sx and sxd to ~/.cargo/bin"
cargo install --path crates/sxd --force
cargo install --path crates/sx --force

SXD="${CARGO_HOME:-$HOME/.cargo}/bin/sxd"

echo
echo "==> Registering sxd as a login auto-start agent"
"$SXD" install

cat <<'EOF'

Done. sxd is running and will start at each login.

  sx run --env .env -- your command     # use it
  sxd uninstall                         # remove the auto-start agent
  launchctl print gui/$(id -u)/dev.sx.sxd   # inspect the service
EOF
