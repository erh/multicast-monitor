#!/usr/bin/env bash
#
# install.sh — fetch the latest mcastwatch release and set it up.
#
#   curl -fsSL https://raw.githubusercontent.com/erh/multicast-monitor/main/install.sh | sudo bash -s -- eno1
#
# With no interface argument it installs the binary and unit but doesn't start
# anything, leaving you to pick the interface yourself.
#
set -euo pipefail

REPO="erh/multicast-monitor"
IFACE="${1:-}"
PREFIX="${PREFIX:-/usr/local/bin}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv6l|armv7l) ARCH=arm ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
log "architecture: ${ARCH}"

command -v curl >/dev/null || die "curl is required"
command -v tar  >/dev/null || die "tar is required"

log "finding latest release"
URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep -o "https://[^\"]*linux-${ARCH}\.tar\.gz" | head -1)
[[ -n "$URL" ]] || die "no release asset found for linux-${ARCH}. Build from source: make install"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
log "downloading $(basename "$URL")"
curl -fsSL "$URL" -o "$TMP/mw.tar.gz"
tar xzf "$TMP/mw.tar.gz" -C "$TMP"

BIN=$(find "$TMP" -name "mcastwatch-linux-${ARCH}" -type f | head -1)
[[ -n "$BIN" ]] || die "binary missing from archive"

install -m 0755 "$BIN" "${PREFIX}/mcastwatch"
log "installed ${PREFIX}/mcastwatch ($(${PREFIX}/mcastwatch -version))"

UNIT=$(find "$TMP" -name 'mcastwatch@.service' -type f | head -1)
if [[ -n "$UNIT" ]] && command -v systemctl >/dev/null; then
  install -m 0644 "$UNIT" /etc/systemd/system/mcastwatch@.service
  systemctl daemon-reload
  log "installed systemd unit"
fi

if [[ -z "$IFACE" ]]; then
  echo
  log "done. Pick an interface and start it:"
  ip -br link show up | awk '{print "      systemctl enable --now mcastwatch@" $1}' \
    | grep -Ev 'mcastwatch@(lo|docker|veth|br-)'
  exit 0
fi

ip link show "$IFACE" &>/dev/null || die "interface '$IFACE' does not exist"
systemctl enable --now "mcastwatch@${IFACE}"
sleep 2
systemctl is-active --quiet "mcastwatch@${IFACE}" \
  || die "service failed to start: journalctl -u mcastwatch@${IFACE} -n 30"

MYIP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
log "running on ${IFACE}"
echo "    dashboard: http://${MYIP:-<this-host>}:8088/"
echo "    logs:      journalctl -u mcastwatch@${IFACE} -f"
