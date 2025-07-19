<p align="center">
  <img src="assets/LANimals_logo.png" alt="LANimals Logo" width="375">
</p>

<h1 align="center">LANimals</h1>

<p align="center">
<b>
A next-gen network situational awareness and LAN threat hunting framework for Linux, Termux, and more.<br>
Battle-tested, scriptable, and built for real red teams.
</b>
</p>

---

## What is LANimals?

**LANimals is a modular, interactive, and scriptable toolkit for rapid LAN reconnaissance, threat hunting, and live network mapping.**  
Unlike traditional recon tools, LANimals is a fully native CLI experience—offering interactive ASCII visualizations, autonomous detection, threat enrichment, and exportable reporting.

---

## Why LANimals is Unique

- Native CLI: Interactive ASCII banners and visual subnet mapping
- One-liner recon: `lanimals recon` for instant network awareness
- Modular commands: Each feature is a standalone script/CLI module
- **GhostScan:** Detects outbound/hidden infrastructure
- Threat enrichment: Live anomaly detection and enrichment via open source intel
- Works on Linux, Kali, and Termux

---

## Features

- Autonomous LAN recon & mapping
- ARP, port, and service fingerprinting
- Real-time traffic tap & analysis
- Threat/rogue device detection
- Loot logging & analytics
- Outbound infra & anomaly detection
- Session reporting/export
- WLAN beacon hunting & dark web host detection
- ...and more!

---

## Install

```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
pip install -r requirements.txt
./install.sh