#!/usr/bin/env bash
# heimdall-install.sh - install / reconfigure Heimdall
#
# Usage:
#   sudo ./heimdall-install.sh
#   sudo ./heimdall-install.sh --mode hybrid
#   sudo ./heimdall-install.sh --uninstall
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/opt/heimdall}"
BINDIR="/usr/local/bin"
SBINDIR="/usr/local/sbin"
MANDIR="/usr/local/share/man/man1"
SYSCONF="/etc/heimdall"
STATEDIR="/var/lib/heimdall"
UNIT="/etc/systemd/system/heimdald.service"
SVCUSER="heimdall"
SVCGROUP="heimdall"

AMBER=$'\033[38;2;224;164;88m'
DIM=$'\033[38;2;107;111;115m'
GREEN=$'\033[38;2;127;176;105m'
RED=$'\033[38;2;200;85;61m'
RESET=$'\033[0m'

say() { printf "  %s\n" "$*"; }
ok() { printf "  %sOK%s  %s\n" "$GREEN" "$RESET" "$*"; }
warn() { printf "  %s!%s  %s\n" "$AMBER" "$RESET" "$*"; }
die() { printf "  %sX%s  %s\n" "$RED" "$RESET" "$*" >&2; exit 1; }
banner() { printf "\n  %sHEIMDALL%s  %s-  installer%s\n\n" "$AMBER" "$RESET" "$DIM" "$RESET"; }

source_dir() {
  if [[ -f "$REPO_DIR/heimdald.py" && -f "$REPO_DIR/safety.yaml" ]]; then
    printf '%s\n' "$REPO_DIR"
  elif [[ -f "$PREFIX/heimdald.py" && -f "$PREFIX/safety.yaml" ]]; then
    printf '%s\n' "$PREFIX"
  else
    die "cannot find Heimdall source files in $REPO_DIR or $PREFIX"
  fi
}

install_if_different() {
  local mode="$1"
  local src="$2"
  local dst="$3"
  if [[ -e "$dst" && "$(readlink -f "$src")" == "$(readlink -f "$dst")" ]]; then
    chmod "$mode" "$dst"
    chown root:root "$dst"
  else
    install -o root -g root -m "$mode" "$src" "$dst"
  fi
}

require_root() {
  [[ ${EUID} -eq 0 ]] || die "must run as root (use: sudo $0)"
}

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die "installer is Linux-only; use --dev on Windows"
}

show_modes() {
  cat <<'EOF'

  How should Heimdall execute commands?

  [1] sandbox   Every command runs inside bwrap. Maximum containment.
                Some raw-socket, kernel, BPF, C2, and wireless tools may fail.

  [2] direct    Commands run on your real system as you. Full capability.
                No containment. Use only on machines you own and understand.

  [3] hybrid    Direct for low-risk read-only ops. Automatic sandbox for
                execution, installs, C2, exploit, and unsafe commands.
                Recommended.

EOF
}

choose_mode_interactive() {
  show_modes
  local choice
  read -r -p "  Choice [3]: " choice
  case "${choice:-3}" in
    1|sandbox) echo "sandbox" ;;
    2|direct) echo "direct" ;;
    3|hybrid) echo "hybrid" ;;
    *) die "invalid choice" ;;
  esac
}

confirm_direct() {
  warn "You selected DIRECT mode."
  warn "Every warn-level action will require typing a confirmation phrase."
  warn "The daemon will refuse to run if logging fails."
  echo
  read -r -p "  Type exactly to confirm: I UNDERSTAND THE RISK
  > " phrase
  [[ "$phrase" == "I UNDERSTAND THE RISK" ]] || die "phrase mismatch - aborted"
}

setup_user() {
  if getent group "$SVCGROUP" >/dev/null; then
    ok "group $SVCGROUP already exists"
  else
    groupadd --system "$SVCGROUP"
    ok "created system group $SVCGROUP"
  fi

  if id "$SVCUSER" >/dev/null 2>&1; then
    ok "user $SVCUSER already exists"
  else
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$SVCGROUP" "$SVCUSER"
    ok "created system user $SVCUSER"
  fi
}

setup_dirs() {
  install -d -o root -g root -m 0755 "$PREFIX"
  install -d -o root -g "$SVCGROUP" -m 0750 "$STATEDIR"
  install -d -o root -g "$SVCGROUP" -m 0750 "$STATEDIR/history"
  install -d -o root -g "$SVCGROUP" -m 0750 "$STATEDIR/evidence"
  install -d -o root -g root -m 0755 "$SYSCONF"
  install -d -o root -g root -m 0755 "$SBINDIR"
  install -d -o root -g root -m 0755 "$MANDIR"
  ok "directories created under $PREFIX, $STATEDIR, $SYSCONF"
}

copy_files() {
  local src
  src="$(source_dir)"
  for file in heimdald.py heimdall.py executor.py scanners.py ui.py dashboard.py lab.py safety.yaml heimdald.service docs/heimdall.1 heimdall-update; do
    [[ -f "$src/$file" ]] || die "missing $src/$file"
  done
  install_if_different 0755 "$src/heimdald.py" "$PREFIX/heimdald.py"
  install_if_different 0755 "$src/heimdall.py" "$PREFIX/heimdall.py"
  install_if_different 0755 "$src/executor.py" "$PREFIX/executor.py"
  install_if_different 0755 "$src/scanners.py" "$PREFIX/scanners.py"
  install_if_different 0755 "$src/ui.py" "$PREFIX/ui.py"
  install_if_different 0755 "$src/dashboard.py" "$PREFIX/dashboard.py"
  install_if_different 0755 "$src/lab.py" "$PREFIX/lab.py"
  install_if_different 0644 "$src/heimdald.service" "$PREFIX/heimdald.service"
  if [[ -f "$src/heimdall-install.sh" ]]; then
    install_if_different 0755 "$src/heimdall-install.sh" "$SBINDIR/heimdall-install"
  else
    install_if_different 0755 "$0" "$SBINDIR/heimdall-install"
  fi
  install_if_different 0755 "$src/heimdall-update" "$SBINDIR/heimdall-update"
  install_if_different 0644 "$src/docs/heimdall.1" "$MANDIR/heimdall.1"
  ln -sf "$PREFIX/heimdall.py" "$BINDIR/heimdall"
  ok "programs installed; $BINDIR/heimdall linked"

  install_if_different 0600 "$src/safety.yaml" "$PREFIX/safety.yaml"
  ok "policy installed at $PREFIX/safety.yaml (root:root 0600)"
}

write_mode() {
  local mode="$1"
  printf '%s\n' "$mode" > "$SYSCONF/mode"
  chmod 0644 "$SYSCONF/mode"
  chown root:root "$SYSCONF/mode"
  ok "mode set to: $mode  ($SYSCONF/mode)"
}

install_unit() {
  local src
  src="$(source_dir)"
  install_if_different 0644 "$src/heimdald.service" "$UNIT"
  systemctl daemon-reload
  ok "systemd unit installed: $UNIT"
}

enable_start() {
  systemctl enable heimdald.service >/dev/null 2>&1
  systemctl restart heimdald.service
  sleep 1
  if systemctl is-active --quiet heimdald.service; then
    ok "heimdald.service active"
  else
    journalctl -u heimdald.service -n 30 --no-pager || true
    die "heimdald.service failed to start"
  fi
}

verify() {
  local socket_ok=0
  for _ in {1..20}; do
    if [[ -S /run/heimdall/bifrost.sock ]]; then
      socket_ok=1
      break
    fi
    sleep 0.25
  done
  if [[ "$socket_ok" == "1" ]]; then
    ok "socket present: /run/heimdall/bifrost.sock"
  else
    warn "socket not visible yet; trying client ping before failing"
    if command -v heimdall >/dev/null 2>&1 && heimdall ping 2>/dev/null | grep -q "daemon alive"; then
      ok "daemon reachable even though socket check raced"
    else
      die "socket missing after start"
    fi
  fi
  if python3 "$PREFIX/heimdald.py" --selftest >/dev/null 2>&1; then
    ok "daemon selftest passed"
  else
    warn "daemon selftest did not run cleanly"
  fi
  if command -v heimdall >/dev/null 2>&1 && heimdall ping 2>/dev/null | grep -q "daemon alive"; then
    ok "client ping succeeded"
  else
    warn "client ping failed - run: heimdall ping"
  fi
}

uninstall() {
  banner
  require_root
  require_linux
  say "uninstalling Heimdall"
  systemctl stop heimdald.service 2>/dev/null || true
  systemctl disable heimdald.service 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  rm -f "$BINDIR/heimdall" "$SBINDIR/heimdall-install" "$SBINDIR/heimdall-update"
  warn "left $PREFIX and $STATEDIR in place - remove manually if you want a clean slate"
  ok "uninstalled"
}

main() {
  local mode_arg=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode) mode_arg="${2:-}"; shift 2 ;;
      --uninstall) uninstall; exit 0 ;;
      --help|-h)
        echo "Usage: sudo $0 [--mode sandbox|direct|hybrid] [--uninstall]"
        exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  banner
  require_root
  require_linux

  local mode="${mode_arg:-}"
  if [[ -z "$mode" ]]; then
    mode="$(choose_mode_interactive)"
  fi
  [[ "$mode" =~ ^(sandbox|direct|hybrid)$ ]] || die "invalid mode: $mode"
  if [[ "$mode" == "direct" ]]; then
    confirm_direct
  fi

  say ""
  say "step 1/6  filesystem"
  setup_user
  setup_dirs
  say ""
  say "step 2/6  programs"
  copy_files
  say ""
  say "step 3/6  mode"
  write_mode "$mode"
  say ""
  say "step 4/6  systemd unit"
  install_unit
  say ""
  say "step 5/6  start"
  enable_start
  say ""
  say "step 6/6  verify"
  verify

  echo
  ok "installation complete"
  echo
  say "Try:"
  say "  heimdall \"list open TCP ports on localhost\""
  say "  heimdall --cmd \"cat /etc/hostname\""
  say "  heimdall mode show"
  say ""
  say "Change mode:"
  say "  sudo heimdall mode set sandbox"
}

main "$@"
