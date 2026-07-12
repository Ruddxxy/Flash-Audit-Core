#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# FlashAudit Installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Ruddxxy/Flash-Audit-Core/main/install.sh | bash
# =============================================================================

VERSION="${FLASHAUDIT_VERSION:-latest}"
INSTALL_DIR="${FLASHAUDIT_INSTALL_DIR:-/usr/local/bin}"
REPO="Ruddxxy/Flash-Audit-Core"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)
            case "$ARCH" in
                x86_64)  NAME="flash_audit-linux-x86_64" ;;
                aarch64) NAME="flash_audit-linux-aarch64" ;;
                arm64)   NAME="flash_audit-linux-aarch64" ;;
                *)       error "Unsupported Linux architecture: $ARCH" ;;
            esac
            EXT="tar.gz"
            ;;
        darwin)
            case "$ARCH" in
                x86_64)  NAME="flash_audit-macos-x86_64" ;;
                arm64)   NAME="flash_audit-macos-aarch64" ;;
                aarch64) NAME="flash_audit-macos-aarch64" ;;
                *)       error "Unsupported macOS architecture: $ARCH" ;;
            esac
            EXT="tar.gz"
            ;;
        *)
            error "Unsupported operating system: $OS (Use Windows PowerShell installer for Windows)"
            ;;
    esac

    info "Detected platform: $OS/$ARCH"
}

# Get latest version from GitHub API
get_latest_version() {
    if [ "$VERSION" = "latest" ]; then
        info "Fetching latest version..."
        VERSION=$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" |
                  grep '"tag_name"' |
                  sed -E 's/.*"v?([^"]+)".*/\1/')
        if [ -z "$VERSION" ]; then
            error "Failed to determine latest version. Check https://github.com/$REPO/releases"
        fi
    fi
    # Remove 'v' prefix if present
    VERSION="${VERSION#v}"
    info "Installing FlashAudit version: $VERSION"
}

# Download and install
install() {
    local DOWNLOAD_URL="https://github.com/$REPO/releases/download/v${VERSION}/${NAME}.${EXT}"
    local TMP_DIR
    TMP_DIR=$(mktemp -d)

    info "Downloading from: $DOWNLOAD_URL"

    if ! curl -sSfL "$DOWNLOAD_URL" -o "$TMP_DIR/flashaudit.tar.gz"; then
        error "Failed to download FlashAudit. Check if version $VERSION exists at https://github.com/$REPO/releases"
    fi

    info "Extracting..."
    tar -xzf "$TMP_DIR/flashaudit.tar.gz" -C "$TMP_DIR"

    # Find the binary
    BINARY=$(find "$TMP_DIR" -name "flash_audit*" -type f ! -name "*.md" ! -name "*.yaml" | head -1)
    if [ -z "$BINARY" ]; then
        error "Binary not found in archive"
    fi

    info "Installing to $INSTALL_DIR..."

    # Check if we need sudo
    if [ -w "$INSTALL_DIR" ]; then
        mv "$BINARY" "$INSTALL_DIR/flash_audit"
        chmod +x "$INSTALL_DIR/flash_audit"
    else
        warn "Requires sudo to install to $INSTALL_DIR"
        sudo mv "$BINARY" "$INSTALL_DIR/flash_audit"
        sudo chmod +x "$INSTALL_DIR/flash_audit"
    fi

    # Cleanup
    rm -rf "$TMP_DIR"

    # Verify installation
    if command -v flash_audit &> /dev/null; then
        info "FlashAudit installed successfully!"
        echo ""
        flash_audit --version 2>/dev/null || echo "  flash_audit v$VERSION"
    else
        warn "Installation complete, but flash_audit not found in PATH"
        warn "Add $INSTALL_DIR to your PATH:"
        echo "    export PATH=\"\$PATH:$INSTALL_DIR\""
    fi
}

main() {
    echo ""
    echo -e "${BLUE}"
    echo "  _____ _           _         _             _ _ _   "
    echo " |  ___| | __ _ ___| |__    / \\  _   _  __| (_)| __| "
    echo " | |_  | |/ _\` / __| '_ \\/ _ \\| | | |/ _\` | | __|"
    echo " |  _| | | (_| \\__ \\ | | / ___ \\ |_| | (_| | | |_ "
    echo " |_|   |_|\\__,_|___/_| |_\\_/ \\_\\__,_|\\__,_||\\__|"
    echo -e "${NC}"
    echo " High-performance secrets scanner"
    echo ""

    detect_platform
    get_latest_version
    install

    echo ""
    info "Get started:"
    echo "    flash_audit /path/to/repo"
    echo "    flash_audit --help"
    echo ""
    echo " Documentation: https://github.com/$REPO"
    echo ""
}

main "$@"
