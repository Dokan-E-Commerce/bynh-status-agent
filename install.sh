#!/bin/sh
# bynh-status-agent installer for Linux with systemd.
#
#   curl -fsSL https://raw.githubusercontent.com/Dokan-E-Commerce/bynh-status-agent/main/install.sh -o install.sh
#   sudo sh install.sh                    # asks for the token without echoing it
#   sudo --preserve-env=BYNH_TOKEN sh install.sh   # or take it from BYNH_TOKEN
#   sudo sh install.sh --uninstall
#
# The token is never accepted as a command-line argument, so it can't end up
# in shell history or the process list. It is stored in a root-only file and
# handed to the service as a systemd credential.
#
# Options:
#   --version X.Y.Z    install a specific release (default: latest)
#   --allow-private    let this agent check private/internal addresses
#   --api-url URL      platform URL (default https://api.bynh.io)
#   --no-start         install but don't enable/start the service
#   --uninstall        stop and remove the service and binary (keeps /etc config)
#   --purge            with --uninstall, also remove /etc/bynh-status-agent
#
# Environment: BYNH_TOKEN, BYNH_AGENT_VERSION (same as --version).

set -eu

REPO="Dokan-E-Commerce/bynh-status-agent"
NAME="bynh-status-agent"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/${NAME}"
CONF_FILE="${CONF_DIR}/${NAME}.toml"
TOKEN_FILE="${CONF_DIR}/token"
UNIT_FILE="/etc/systemd/system/${NAME}.service"

VERSION="${BYNH_AGENT_VERSION:-latest}"
ALLOW_PRIVATE="false"
API_URL=""
START="yes"
ACTION="install"
PURGE="no"

say() { printf '%s\n' "$*"; }
# Escapes a value for a TOML basic string (backslash and double quote).
toml_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="${2#v}"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; VERSION="${VERSION#v}"; shift ;;
        --allow-private) ALLOW_PRIVATE="true"; shift ;;
        --api-url) [ $# -ge 2 ] || die "--api-url needs a value"; API_URL="$2"; shift 2 ;;
        --api-url=*) API_URL="${1#*=}"; shift ;;
        --no-start) START="no"; shift ;;
        --uninstall) ACTION="uninstall"; shift ;;
        --purge) PURGE="yes"; shift ;;
        --token|--token=*) die "the token is not accepted as an argument; set BYNH_TOKEN or enter it when asked" ;;
        -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

# --- validate options before touching anything --------------------------------
if [ "$VERSION" != "latest" ]; then
    printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
        || die "--version must look like 1.2.3"
fi
if [ -n "$API_URL" ]; then
    # Only characters that are safe inside a TOML string and a URL.
    printf '%s\n' "$API_URL" | grep -Eq '^[]A-Za-z0-9._~:/?#@!$&()*+,;=%[-]+$' \
        && [ "$(printf '%s' "$API_URL" | wc -l)" -eq 0 ] \
        || die "--api-url contains characters that aren't allowed"
    case "$API_URL" in
        https://*) ;;
        http://127.0.0.1|http://127.0.0.1[:/]*|http://localhost|http://localhost[:/]*|http://\[::1\]|http://\[::1\][:/]*) ;;
        *) die "--api-url must use https:// (plain http is only accepted for loopback addresses)" ;;
    esac
fi

[ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh)"
[ "$(uname -s)" = "Linux" ] || die "this installer supports Linux with systemd; on other systems use the release binary or the Docker image"
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) not found; use the Docker image or run the binary under your init system"

uninstall() {
    if systemctl list-unit-files "${NAME}.service" >/dev/null 2>&1; then
        systemctl disable --now "${NAME}.service" >/dev/null 2>&1 || true
    fi
    rm -f "$UNIT_FILE" "${BIN_DIR}/${NAME}"
    systemctl daemon-reload
    if [ "$PURGE" = "yes" ]; then
        rm -rf "$CONF_DIR"
        say "Removed ${NAME}, its service and ${CONF_DIR}."
    else
        say "Removed ${NAME} and its service. Configuration kept in ${CONF_DIR} (use --purge to delete it)."
    fi
}

if [ "$ACTION" = "uninstall" ]; then
    uninstall
    exit 0
fi

case "$(uname -m)" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) die "unsupported architecture $(uname -m); build from source (see README)" ;;
esac
TARGET="${ARCH}-unknown-linux-musl"
ASSET="${NAME}-${TARGET}"
if [ "$VERSION" = "latest" ]; then
    BASE="https://github.com/${REPO}/releases/latest/download"
else
    BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
fi

download() { # url dest
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$2" "$1"
    else
        die "need curl or wget"
    fi
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "need sha256sum or shasum to verify the download"
    fi
}

# --- token -------------------------------------------------------------------
TOKEN="${BYNH_TOKEN:-}"
if [ -z "$TOKEN" ] && [ ! -s "$TOKEN_FILE" ]; then
    if [ -r /dev/tty ]; then
        printf 'bynh agent token (from Settings → Agents): ' > /dev/tty
        trap 'stty echo < /dev/tty 2>/dev/null' EXIT INT TERM
        stty -echo < /dev/tty 2>/dev/null || true
        IFS= read -r TOKEN < /dev/tty || true
        stty echo < /dev/tty 2>/dev/null || true
        printf '\n' > /dev/tty
    fi
    [ -n "$TOKEN" ] || die "no token: set BYNH_TOKEN or run interactively"
fi
if [ -n "$TOKEN" ]; then
    case "$TOKEN" in
        bynh_agt_*) ;;
        *) die "the token should start with bynh_agt_" ;;
    esac
    case "$TOKEN" in
        *[[:space:]]*) die "the token contains whitespace" ;;
    esac
fi

# --- download and verify -----------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; stty echo < /dev/tty 2>/dev/null || true' EXIT INT TERM
say "Downloading ${ASSET} (${VERSION})…"
download "${BASE}/${ASSET}" "${TMP}/${ASSET}"
download "${BASE}/SHA256SUMS" "${TMP}/SHA256SUMS"
EXPECTED="$(awk -v f="$ASSET" '{ n=$2; sub(/^\*/, "", n); if (n == f) print $1 }' "${TMP}/SHA256SUMS")"
[ -n "$EXPECTED" ] || die "${ASSET} is not listed in SHA256SUMS"
ACTUAL="$(sha256 "${TMP}/${ASSET}")"
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for ${ASSET} (expected ${EXPECTED}, got ${ACTUAL})"
say "Checksum verified."

install -d -m 0755 "$BIN_DIR"
install -m 0755 "${TMP}/${ASSET}" "${BIN_DIR}/${NAME}.new"
mv -f "${BIN_DIR}/${NAME}.new" "${BIN_DIR}/${NAME}"
"${BIN_DIR}/${NAME}" version

# --- configuration -----------------------------------------------------------
install -d -m 0755 "$CONF_DIR"
# An existing directory keeps whatever owner/mode it had; make it root's.
chown root:root "$CONF_DIR"
chmod 0755 "$CONF_DIR"
if [ -n "$TOKEN" ]; then
    (
        umask 077
        printf '%s\n' "$TOKEN" > "${TOKEN_FILE}.new"
    )
    chown root:root "${TOKEN_FILE}.new"
    mv -f "${TOKEN_FILE}.new" "$TOKEN_FILE"
    say "Token saved to ${TOKEN_FILE} (root only)."
else
    chown root:root "$TOKEN_FILE"
    chmod 0600 "$TOKEN_FILE"
    say "Keeping the existing token in ${TOKEN_FILE}."
fi
unset TOKEN

if [ ! -f "$CONF_FILE" ]; then
    {
        say "# bynh-status-agent settings. The token is in ${TOKEN_FILE}, not here."
        say "# Every key is optional; BYNH_* environment variables override them."
        if [ -n "$API_URL" ]; then
            say "api_url = \"$(toml_escape "$API_URL")\""
        else
            say "# api_url = \"https://api.bynh.io\""
        fi
        say "allow_private = ${ALLOW_PRIVATE}   # true for on-premise agents checking internal hosts"
        say "report_ip = true"
        say "concurrency = 64"
    } > "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
    say "Wrote ${CONF_FILE}."
else
    say "Keeping the existing ${CONF_FILE}."
    if [ "$ALLOW_PRIVATE" = "true" ] || [ -n "$API_URL" ]; then
        say "note: --allow-private/--api-url only apply to a new config file; edit ${CONF_FILE} to change them."
    fi
fi

# --- systemd unit ------------------------------------------------------------
install -d -m 0755 "$(dirname "$UNIT_FILE")"
cat > "$UNIT_FILE" <<'UNIT'
# Keep identical to the copy in install.sh (CI checks).
[Unit]
Description=bynh uptime monitoring agent
Documentation=https://github.com/Dokan-E-Commerce/bynh-status-agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bynh-status-agent run --config /etc/bynh-status-agent/bynh-status-agent.toml
# The token lives in a root-only file and reaches the agent as a systemd
# credential ($CREDENTIALS_DIRECTORY/bynh-token), never on the command line.
LoadCredential=bynh-token:/etc/bynh-status-agent/token
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=15

# Identity: a throwaway user allocated at start, no home, no state.
DynamicUser=yes
PrivateUsers=yes
UMask=0077

# Hardening
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM

# Resources: each running check holds one or two sockets.
LimitNOFILE=65536
MemoryMax=128M
TasksMax=64

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$UNIT_FILE"
systemctl daemon-reload

if [ "$START" = "yes" ]; then
    systemctl enable "${NAME}.service" >/dev/null 2>&1
    systemctl restart "${NAME}.service"
    say "${NAME} is running. Logs: journalctl -u ${NAME} -f"
else
    say "Installed. Start it with: systemctl enable --now ${NAME}"
fi
