#!/usr/bin/env bash
set -Eeuo pipefail

# Reconmancer v0.1.4 installer
# Supported: Kali Linux and Debian-based Linux distributions.
# Installs Reconmancer, Python dependencies, Chromium, Go, PDTM,
# HTTPX, Katana, Nuclei, and the managed ProjectDiscovery nuclei-templates repo.
# It intentionally does not install a systemd service or expose the app publicly.

INSTALL_ROOT="/opt/reconmancer"
PD_BIN_DIR="/root/.pdtm/go/bin"
MANAGED_TEMPLATES_DIR="$INSTALL_ROOT/templates/nuclei-templates-projectdiscovery"
TOOLS_CONFIG="$INSTALL_ROOT/config/tools.yaml"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

info()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
ok()    { printf '\033[1;32m%s\033[0m\n' "$*"; }
warn()  { printf '\033[1;33m%s\033[0m\n' "$*"; }
fail()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
section(){ echo; echo "============================================================"; echo " $*"; echo "============================================================"; echo; }

[[ "${EUID}" -eq 0 ]] || fail "Run this installer as root (sudo ./install.sh)."
[[ "$(uname -s)" == "Linux" ]] || fail "This installer currently supports Linux only."
command -v apt-get >/dev/null 2>&1 || fail "This installer currently requires apt/apt-get."

case "$(uname -m)" in
  x86_64|amd64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *) fail "Unsupported CPU architecture: $(uname -m)" ;;
esac

section "Reconmancer v0.1.4 installer"
echo "Source:            $SOURCE_DIR"
echo "Install path:      $INSTALL_ROOT"
echo "PD binaries:       $PD_BIN_DIR"

section "Installing system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  git \
  build-essential \
  python3 \
  python3-dev \
  python3-pip \
  python3-venv \
  sqlite3 \
  chromium \
  zstd \
  unzip \
  tar
ok "System dependencies installed."

section "Installing Reconmancer source"
if [[ "$SOURCE_DIR" != "$INSTALL_ROOT" ]]; then
  if [[ -d "$INSTALL_ROOT" ]] && [[ -n "$(find "$INSTALL_ROOT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    fail "$INSTALL_ROOT already contains files. Move/remove the existing installation before running this installer."
  fi

  mkdir -p "$INSTALL_ROOT"

  tar \
    --exclude='./venv' \
    --exclude='./projects/*' \
    --exclude='./config/tools.yaml' \
    --exclude='./templates/nuclei-templates-projectdiscovery' \
    --exclude='./secrets' \
    --exclude='./temp' \
    --exclude='./logs' \
    --exclude='./__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    -cf - -C "$SOURCE_DIR" . \
  | tar -xf - -C "$INSTALL_ROOT"
fi

mkdir -p \
  "$INSTALL_ROOT/projects" \
  "$INSTALL_ROOT/templates" \
  "$INSTALL_ROOT/temp" \
  "$INSTALL_ROOT/config"

touch "$INSTALL_ROOT/projects/.gitkeep" "$INSTALL_ROOT/templates/.gitkeep"
ok "Reconmancer source installed."

section "Installing latest stable Go"
GO_INFO="$(python3 - "$GO_ARCH" <<'PY'
import json
import sys
import urllib.request

arch = sys.argv[1]
request = urllib.request.Request(
    "https://go.dev/dl/?mode=json",
    headers={"User-Agent": "Reconmancer-Installer/0.1.4"},
)
with urllib.request.urlopen(request, timeout=30) as response:
    releases = json.load(response)

for release in releases:
    if not release.get("stable", False):
        continue
    for item in release.get("files", []):
        if (
            item.get("os") == "linux"
            and item.get("arch") == arch
            and item.get("kind") == "archive"
        ):
            print(release["version"])
            print(item["filename"])
            print(item["sha256"])
            raise SystemExit(0)

raise SystemExit("Could not determine the latest stable Go release.")
PY
)"

GO_VERSION="$(printf '%s\n' "$GO_INFO" | sed -n '1p')"
GO_ARCHIVE="$(printf '%s\n' "$GO_INFO" | sed -n '2p')"
GO_SHA256="$(printf '%s\n' "$GO_INFO" | sed -n '3p')"

[[ -n "$GO_VERSION" && -n "$GO_ARCHIVE" && -n "$GO_SHA256" ]] || fail "Unable to determine the latest stable Go release."

echo "Installing $GO_VERSION for linux/$GO_ARCH"
GO_TMP="$(mktemp -d)"
trap 'rm -rf "$GO_TMP"' EXIT

curl --fail --location --retry 3 --retry-delay 2 \
  --output "$GO_TMP/$GO_ARCHIVE" \
  "https://go.dev/dl/$GO_ARCHIVE"

printf '%s  %s\n' "$GO_SHA256" "$GO_TMP/$GO_ARCHIVE" | sha256sum -c -
rm -rf /usr/local/go
tar -C /usr/local -xzf "$GO_TMP/$GO_ARCHIVE"

export PATH="/usr/local/go/bin:/root/go/bin:/usr/local/bin:$PATH"
cat >/etc/profile.d/reconmancer-go.sh <<'PROFILE'
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
PROFILE
chmod 644 /etc/profile.d/reconmancer-go.sh
ok "$(go version)"

section "Installing ProjectDiscovery PDTM"
GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
command -v pdtm >/dev/null 2>&1 || fail "PDTM installation failed."
pdtm -version || true
ok "PDTM installed."

section "Installing HTTPX, Katana and Nuclei"
mkdir -p "$PD_BIN_DIR"
pdtm -bp "$PD_BIN_DIR" -i httpx,katana,nuclei -nc

for tool in httpx katana nuclei; do
  [[ -x "$PD_BIN_DIR/$tool" ]] || fail "$tool was not installed at $PD_BIN_DIR/$tool"
done
ok "ProjectDiscovery tools installed."

section "Creating Reconmancer tool configuration"
cat >"$TOOLS_CONFIG" <<EOF_TOOLS
tools:
  httpx:
    path: $PD_BIN_DIR/httpx
  katana:
    path: $PD_BIN_DIR/katana
  nuclei:
    path: $PD_BIN_DIR/nuclei
EOF_TOOLS
chmod 644 "$TOOLS_CONFIG"
ok "Created $TOOLS_CONFIG"

section "Creating Python virtual environment"
rm -rf "$INSTALL_ROOT/venv"
python3 -m venv "$INSTALL_ROOT/venv"
"$INSTALL_ROOT/venv/bin/python" -m pip install --upgrade pip setuptools wheel
[[ -f "$INSTALL_ROOT/requirements.txt" ]] || fail "requirements.txt was not found."
"$INSTALL_ROOT/venv/bin/python" -m pip install -r "$INSTALL_ROOT/requirements.txt"
ok "Python environment installed."

section "Installing managed ProjectDiscovery Nuclei templates"
rm -rf "$MANAGED_TEMPLATES_DIR"
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$MANAGED_TEMPLATES_DIR"
ok "Managed nuclei-templates checkout installed."

section "Initializing Nuclei default template store"
if ! "$PD_BIN_DIR/nuclei" -ut; then
  warn "Nuclei default template initialization returned an error. The managed ProjectDiscovery checkout is still installed."
fi

section "Validating installation"
echo "Go:"
go version

echo; echo "PDTM:"
pdtm -version || true

echo; echo "HTTPX:"
"$PD_BIN_DIR/httpx" -version

echo; echo "Katana:"
"$PD_BIN_DIR/katana" -version

echo; echo "Nuclei:"
"$PD_BIN_DIR/nuclei" -version

echo; echo "Chromium:"
chromium --version

echo; echo "Python:"
"$INSTALL_ROOT/venv/bin/python" --version

echo; info "Compiling Reconmancer Python source..."
"$INSTALL_ROOT/venv/bin/python" -m compileall -q "$INSTALL_ROOT/reconmancer" "$INSTALL_ROOT/scripts"
ok "Python compilation passed."

info "Parsing Jinja templates..."
INSTALL_ROOT="$INSTALL_ROOT" "$INSTALL_ROOT/venv/bin/python" <<'PY'
import os
from pathlib import Path
from jinja2 import Environment

root = Path(os.environ["INSTALL_ROOT"])
env = Environment()
count = 0
for location in (root / "reconmancer" / "web" / "templates", root / "templates"):
    if not location.exists():
        continue
    for path in location.rglob("*.html"):
        env.parse(path.read_text(encoding="utf-8", errors="replace"))
        count += 1
print(f"Parsed {count} Jinja template(s).")
PY
ok "Template validation passed."

# Remove compile caches created by validation.
find "$INSTALL_ROOT" -type d -name '__pycache__' -prune -exec rm -rf -- {} + 2>/dev/null || true
find "$INSTALL_ROOT" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete 2>/dev/null || true
chmod +x "$INSTALL_ROOT/install.sh" 2>/dev/null || true

section "Reconmancer installation complete"
ok "Reconmancer is ready."
echo
echo "Start it with:"
echo "  cd $INSTALL_ROOT"
echo "  source venv/bin/activate"
echo "  python -m reconmancer.main"
echo
echo "Then browse locally to:"
echo "  http://127.0.0.1:8000"
echo
echo "For a VPS, from your own PC use:"
echo "  ssh -L 8000:127.0.0.1:8000 root@YOUR_VPS_IP"
echo
echo "Then open:"
echo "  http://127.0.0.1:8000"
