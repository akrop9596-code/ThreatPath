#!/usr/bin/env bash
set -e
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$APP_DIR/launch-threatpath.sh"

ICON_PATH="$APP_DIR/threatpath-icon.svg"
if [ ! -f "$ICON_PATH" ]; then
  ICON_PATH="security-high"
fi

DESKTOP_DIR="$HOME/Desktop"
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_DIR" "$APPS_DIR"

DESKTOP_FILE="$DESKTOP_DIR/ThreatPath-AI.desktop"
MENU_FILE="$APPS_DIR/ThreatPath-AI.desktop"

cat << EOF > "$DESKTOP_FILE"
[Desktop Entry]
Version=1.0
Type=Application
Name=ThreatPath AI
GenericName=Cybersecurity Investigation Platform
Comment=Launch ThreatPath AI System, Network & Code Security Platform
Exec=/usr/bin/env bash "$APP_DIR/launch-threatpath.sh"
Path=$APP_DIR
Icon=$ICON_PATH
Terminal=true
Categories=Security;System;Network;
StartupNotify=true
EOF

chmod +x "$DESKTOP_FILE"
cp "$DESKTOP_FILE" "$MENU_FILE"
chmod +x "$MENU_FILE"

# Mark desktop shortcut as trusted on XFCE / GNOME (Kali Linux default)
if command -v gio >/dev/null 2>&1; then
  gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
fi

echo "=========================================================="
echo "  [OK] ThreatPath AI Application Installed Successfully!"
echo "  -> Desktop Shortcut : $DESKTOP_FILE"
echo "  -> System App Menu  : $MENU_FILE"
echo "=========================================================="
echo "  You can now double-click 'ThreatPath AI' on your Desktop!"
