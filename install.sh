#!/usr/bin/env bash
# BagaHoldin — dependency installer
# Run as root or with sudo on Kali Linux.
set -euo pipefail

# ── helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${BLUE}[→]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }
need_cmd() { command -v "$1" &>/dev/null || die "$1 not found after install — check your PATH"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 0. sanity checks ──────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && SUDO="sudo" || SUDO=""
grep -qi kali /etc/os-release 2>/dev/null || warn "Not running on Kali Linux — proceeding anyway"

echo -e "${BLUE}BagaHoldin — installing dependencies${NC}"
echo "────────────────────────────────────────────"

# ── 1. apt update ─────────────────────────────────────────────────────────────
info "Updating package lists…"
$SUDO apt-get update -qq

# ── 2. build toolchain (CGo required by go-sqlite3) ───────────────────────────
if ! dpkg -s build-essential &>/dev/null 2>&1; then
    info "Installing build-essential (required for CGo/SQLite)…"
    $SUDO apt-get install -y build-essential
fi
ok "build-essential"

# ── 3. curl (needed for Go/Node downloads) ────────────────────────────────────
if ! command -v curl &>/dev/null; then
    info "Installing curl…"
    $SUDO apt-get install -y curl
fi
ok "curl"

# ── 4. apt-installable pentesting tools not in default Kali ───────────────────
APT_TOOLS=(wpscan hostapd-mana hcxtools python3-pam enum4linux crackmapexec evil-winrm responder impacket-scripts)
for pkg in "${APT_TOOLS[@]}"; do
    if dpkg -s "$pkg" &>/dev/null 2>&1; then
        ok "$pkg (already installed)"
    else
        info "Installing $pkg…"
        $SUDO apt-get install -y "$pkg" 2>/dev/null || warn "$pkg not available in apt — install manually if needed"
    fi
done

# ── 5. feroxbuster ────────────────────────────────────────────────────────────
if command -v feroxbuster &>/dev/null; then
    ok "feroxbuster (already installed)"
else
    DEB=$(ls "$SCRIPT_DIR"/feroxbuster_*.deb 2>/dev/null | head -1 || true)
    if [[ -n "$DEB" ]]; then
        info "Installing feroxbuster from local .deb ($DEB)…"
        $SUDO dpkg -i "$DEB"
    else
        info "Installing feroxbuster from apt…"
        $SUDO apt-get install -y feroxbuster 2>/dev/null || warn "feroxbuster not available — download from https://github.com/epi052/feroxbuster/releases"
    fi
fi
command -v feroxbuster &>/dev/null && ok "feroxbuster" || warn "feroxbuster not installed"

# ── 5b. kerbrute (not in apt — check PATH only, guide user if missing) ────────
if command -v kerbrute &>/dev/null; then
    ok "kerbrute"
else
    warn "kerbrute not found — download the latest release from https://github.com/ropnop/kerbrute/releases and place in /usr/local/bin/kerbrute"
fi

# ── 6. Go runtime ─────────────────────────────────────────────────────────────
GO_MIN_MAJOR=1
GO_MIN_MINOR=21

version_ge() {
    # returns 0 (true) if version $1 >= $2.$3
    local ver="$1" maj="$2" min="$3"
    local vmaj vmin
    vmaj=$(echo "$ver" | cut -d. -f1)
    vmin=$(echo "$ver" | cut -d. -f2)
    [[ "$vmaj" -gt "$maj" ]] || { [[ "$vmaj" -eq "$maj" ]] && [[ "$vmin" -ge "$min" ]]; }
}

install_go_tarball() {
    info "Fetching latest Go release from go.dev…"
    LATEST=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    [[ -n "$LATEST" ]] || die "Could not determine latest Go version"
    info "Downloading $LATEST…"
    TMP=$(mktemp -d)
    curl -fsSL "https://go.dev/dl/${LATEST}.linux-amd64.tar.gz" -o "$TMP/go.tar.gz"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$TMP/go.tar.gz"
    rm -rf "$TMP"
    export PATH="/usr/local/go/bin:$PATH"
    echo 'export PATH=$PATH:/usr/local/go/bin' | $SUDO tee /etc/profile.d/golang.sh > /dev/null
    ok "Go $LATEST installed to /usr/local/go"
}

if command -v go &>/dev/null; then
    GOVER=$(go version | awk '{print $3}' | sed 's/go//')
    if version_ge "$GOVER" "$GO_MIN_MAJOR" "$GO_MIN_MINOR"; then
        ok "Go $GOVER"
    else
        warn "Go $GOVER is too old (need >= $GO_MIN_MAJOR.$GO_MIN_MINOR) — upgrading from go.dev"
        install_go_tarball
    fi
else
    info "Go not found — trying apt first…"
    $SUDO apt-get install -y golang-go 2>/dev/null || true
    if command -v go &>/dev/null; then
        GOVER=$(go version | awk '{print $3}' | sed 's/go//')
        if version_ge "$GOVER" "$GO_MIN_MAJOR" "$GO_MIN_MINOR"; then
            ok "Go $GOVER (apt)"
        else
            warn "apt Go $GOVER too old — installing from go.dev"
            install_go_tarball
        fi
    else
        install_go_tarball
    fi
fi
need_cmd go

# ── 7. Node.js 18+ ────────────────────────────────────────────────────────────
NODE_MIN=18

install_node() {
    info "Installing Node.js 20 via NodeSource…"
    curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO bash -
    $SUDO apt-get install -y nodejs
}

if command -v node &>/dev/null; then
    NODEVER=$(node --version | sed 's/v//' | cut -d. -f1)
    if [[ "$NODEVER" -ge "$NODE_MIN" ]]; then
        ok "Node.js v$(node --version | sed 's/v//')"
    else
        warn "Node.js v$NODEVER is too old (need >= $NODE_MIN) — upgrading via NodeSource"
        install_node
    fi
else
    install_node
fi
need_cmd node
need_cmd npm
ok "npm $(npm --version)"

# ── 8. Go module dependencies ─────────────────────────────────────────────────
info "Downloading Go module dependencies…"
(cd "$SCRIPT_DIR/backend" && go mod download)
ok "Go modules downloaded"

# ── 9. Frontend npm install + production build ────────────────────────────────
info "Installing frontend npm packages…"
(cd "$SCRIPT_DIR/frontend" && npm install --silent)
info "Building frontend (production)…"
(cd "$SCRIPT_DIR/frontend" && npm run build 2>&1 | tail -3)
ok "Frontend built → frontend/build/"

# ── 10. Copy frontend build into backend for embedding ────────────────────────
info "Copying frontend build into backend/ui for embedding…"
rm -rf "$SCRIPT_DIR/backend/ui"
cp -r "$SCRIPT_DIR/frontend/build" "$SCRIPT_DIR/backend/ui"
ok "Frontend ready to embed → backend/ui/"

# ── 11. Build backend binary (embeds backend/ui/ into the binary) ─────────────
info "Building backend binary…"
(cd "$SCRIPT_DIR/backend" && go build -o bagaholdin .)
ok "Backend binary → backend/bagaholdin (single binary, frontend embedded)"

# ── verify default Kali tools present ─────────────────────────────────────────
echo ""
echo "Checking default Kali tools…"
KALI_TOOLS=(msfconsole msfvenom searchsploit nmap airmon-ng airodump-ng aireplay-ng hashcat hydra sqlmap kerbrute enum4linux crackmapexec evil-winrm responder)
ALL_PRESENT=true
for t in "${KALI_TOOLS[@]}"; do
    if command -v "$t" &>/dev/null; then
        ok "$t"
    else
        warn "$t not found — ensure metasploit-framework / aircrack-ng / kali-linux-default is installed"
        ALL_PRESENT=false
    fi
done
$ALL_PRESENT || warn "Some default Kali tools are missing. Run: sudo apt install kali-linux-default"

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}────────────────────────────────────────────${NC}"
echo -e "${GREEN}Installation complete.${NC}"
echo ""
echo "  Start the app:  cd backend && sudo ./bagaholdin"
echo ""
echo "  Default listen: http://localhost:8080"
echo -e "${GREEN}────────────────────────────────────────────${NC}"
