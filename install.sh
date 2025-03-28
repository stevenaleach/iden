#!/bin/bash

set -e

echo "[IDEN] Building release binary..."
cargo build --release

BIN_DIR="$HOME/bin"
EXECUTABLE="$BIN_DIR/iden"
TARGET="target/release/iden"

mkdir -p "$BIN_DIR"
cp "$TARGET" "$EXECUTABLE"
echo "[IDEN] Installed binary to $EXECUTABLE"

# Copy basenet Python components
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/basenet.py" "$BIN_DIR/basenet.py"
cp "$SCRIPT_DIR/basenet" "$BIN_DIR/basenet"
chmod +x "$BIN_DIR/basenet"
echo "[IDEN] Installed basenet.py and launcher to $BIN_DIR"

# Check if ~/bin is in PATH
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    SHELL_RC=""
    if [ -n "$BASH_VERSION" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        SHELL_RC="$HOME/.zshrc"
    fi

    if [ -n "$SHELL_RC" ]; then
        echo "[IDEN] Adding $BIN_DIR to PATH in $SHELL_RC"
        echo 'export PATH="$HOME/bin:$PATH"' >> "$SHELL_RC"
        echo "✅ Please restart your terminal or run: source $SHELL_RC"
    else
        echo "[IDEN] Warning: couldn't detect shell config file."
        echo "         Please add '$BIN_DIR' to your PATH manually."
    fi
else
    echo "[IDEN] $BIN_DIR already in PATH."
fi

echo "[IDEN] Install complete. You can now run:"
echo "  → iden"
echo "  → basenet"

