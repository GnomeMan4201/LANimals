#!/usr/bin/env bash
# LANimals Nexus — compatibility launcher
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec bash "$ROOT/lan.sh"
