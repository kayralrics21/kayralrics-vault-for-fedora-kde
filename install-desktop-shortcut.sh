#!/usr/bin/env bash
set -euo pipefail
APP_DIR="$(dirname "$(readlink -f "$0")")"
DESKTOP="$HOME/.local/share/applications/kayralrics-vault.desktop"
mkdir -p "$(dirname "$DESKTOP")"
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=kayralrics vault
Comment=Offline AES-256 encrypted notes and storage
Exec=$APP_DIR/run.sh
Path=$APP_DIR
Terminal=false
Categories=Utility;Office;
StartupNotify=true
EOF
chmod 644 "$DESKTOP"
echo "Desktop launcher installed: $DESKTOP"
