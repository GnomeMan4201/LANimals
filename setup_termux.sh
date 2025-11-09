#!/data/data/com.termux/files/usr/bin/bash

echo "[✓] Setting up LANimals for Termux..."

pkg update -y && pkg upgrade -y
pkg install python git clang -y
pkg install imagemagick -y
pip install rich

echo "[✓] Dependencies installed."
echo "[✓] You can now run: python launch.py"
