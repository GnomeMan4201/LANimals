#!/usr/bin/env bash
# ==========================================================
# LANimals Uninstaller
# Author: GnomeMan4201
# Purpose: Cleanly remove LANimals from system paths
# ==========================================================

set -e

echo "🧹 LANimals Uninstaller — removing all traces..."

# Ask for confirmation
read -p "Are you sure you want to completely remove LANimals? [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted. LANimals remains installed."
    exit 0
fi

# Remove symlinks and CLI entries
echo "[1/6] Removing global CLI entries..."
sudo rm -f /usr/local/bin/lanimals* /usr/bin/lanimals* ~/.local/bin/lanimals* 2>/dev/null || true

# Remove global directories
echo "[2/6] Removing global directories..."
sudo rm -rf /opt/lanimals /usr/share/lanimals /etc/lanimals 2>/dev/null || true

# Remove user configuration & cache
echo "[3/6] Cleaning user configs and cache..."
rm -rf ~/.config/lanimals ~/.cache/lanimals ~/.local/share/lanimals 2>/dev/null || true

# Remove source directory if exists
if [ -d "$HOME/LANimals" ]; then
    echo "[4/6] Removing source directory at ~/LANimals"
    rm -rf "$HOME/LANimals"
fi

# Handle .deb uninstall if installed via dpkg
echo "[5/6] Checking for .deb package traces..."
if dpkg -l | grep -q lanimals; then
    sudo dpkg --purge lanimals || true
    sudo apt remove -y lanimals || true
fi

# Optional: remove desktop shortcuts or menu entries
echo "[6/6] Removing leftover desktop entries..."
sudo find /usr/share/applications ~/.local/share/applications -type f -name "*lanimals*.desktop" -delete 2>/dev/null || true

echo
echo "✅ LANimals has been successfully uninstalled."
echo "You can re-install anytime via:"
echo "  git clone https://github.com/GnomeMan4201/LANimals.git && cd LANimals && sudo ./install.sh"
echo
