#!/usr/bin/env bash
set -euo pipefail

# VX Security Scanner — Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/MakFly/vx/main/install.sh | bash

VERSION="${VX_VERSION:-latest}"
REPO="MakFly/vx"
INSTALL_DIR="${VX_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="vx"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

# Detect OS and architecture
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)   os="linux" ;;
        Darwin*)  os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *)        error "Unsupported OS: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        aarch64|arm64)  arch="arm64" ;;
        *)              error "Unsupported architecture: $(uname -m)" ;;
    esac

    echo "${os}-${arch}"
}

# Get the latest release tag from GitHub
get_latest_version() {
    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    if [ -z "$latest" ]; then
        error "Could not determine latest version. Set VX_VERSION=vX.Y.Z manually."
    fi
    echo "$latest"
}

# Check for required tools
check_deps() {
    for cmd in curl tar; do
        if ! command -v "$cmd" &>/dev/null; then
            error "'$cmd' is required but not installed."
        fi
    done
}

# Build from source if no release binary available
build_from_source() {
    info "No pre-built binary found. Building from source..."

    if ! command -v go &>/dev/null; then
        error "Go is required to build from source. Install it from https://go.dev/dl/"
    fi

    local go_version
    go_version=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
    local major minor
    major=$(echo "$go_version" | cut -d. -f1)
    minor=$(echo "$go_version" | cut -d. -f2)
    if [ "$major" -lt 1 ] || ([ "$major" -eq 1 ] && [ "$minor" -lt 22 ]); then
        error "Go 1.22+ required, found $(go version)"
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    info "Cloning ${REPO}..."
    git clone --depth 1 "https://github.com/${REPO}.git" "$tmpdir/vx" 2>/dev/null

    info "Building..."
    cd "$tmpdir/vx"
    go build -ldflags "-s -w" -o "${BINARY_NAME}" ./main.go

    install_binary "$tmpdir/vx/${BINARY_NAME}"
}

# Download pre-built binary from GitHub releases
download_release() {
    local platform="$1"
    local version="$2"
    local os arch ext=""

    os=$(echo "$platform" | cut -d- -f1)
    arch=$(echo "$platform" | cut -d- -f2)

    if [ "$os" = "windows" ]; then
        ext=".exe"
    fi

    local asset_name="vx-${os}-${arch}${ext}"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${asset_name}"

    info "Downloading ${asset_name} (${version})..."

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    local http_code
    http_code=$(curl -fsSL -w "%{http_code}" -o "$tmpdir/${BINARY_NAME}${ext}" "$download_url" 2>/dev/null || true)

    if [ "$http_code" != "200" ] || [ ! -s "$tmpdir/${BINARY_NAME}${ext}" ]; then
        warn "No release binary found for ${platform} ${version}."
        build_from_source
        return
    fi

    chmod +x "$tmpdir/${BINARY_NAME}${ext}"
    install_binary "$tmpdir/${BINARY_NAME}${ext}"
}

# Install binary to the target directory
install_binary() {
    local src="$1"

    if [ -w "$INSTALL_DIR" ]; then
        cp "$src" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo cp "$src" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    ok "VX installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

# Verify installation
verify() {
    if command -v "$BINARY_NAME" &>/dev/null; then
        local ver
        ver=$("$BINARY_NAME" version 2>/dev/null || echo "unknown")
        ok "Installed: $ver"
        echo ""
        echo -e "  ${GREEN}Get started:${NC}"
        echo "    vx scan https://example.com     # Remote scan"
        echo "    vx audit ./my-project            # Local audit"
        echo "    vx                               # Interactive mode"
        echo ""
    else
        warn "VX was installed but '${BINARY_NAME}' is not in PATH."
        warn "Add ${INSTALL_DIR} to your PATH or run: ${INSTALL_DIR}/${BINARY_NAME}"
    fi
}

# Main
main() {
    echo ""
    echo "  ██╗   ██╗██╗  ██╗"
    echo "  ██║   ██║╚██╗██╔╝"
    echo "  ██║   ██║ ╚███╔╝   Installer"
    echo "  ╚██╗ ██╔╝ ██╔██╗"
    echo "   ╚████╔╝ ██╔╝ ██╗"
    echo "    ╚═══╝  ╚═╝  ╚═╝"
    echo ""

    check_deps

    local platform
    platform=$(detect_platform)
    info "Detected platform: ${platform}"

    if [ "$VERSION" = "latest" ]; then
        VERSION=$(get_latest_version 2>/dev/null || echo "")
    fi

    if [ -n "$VERSION" ]; then
        info "Version: ${VERSION}"
        download_release "$platform" "$VERSION"
    else
        info "No release found — building from source."
        build_from_source
    fi

    verify
}

main "$@"
