# LANimals

A next-gen network situational awareness and LAN threat hunting framework.  
Modular. Scriptable. Battle-tested. All killer, no filler.

## Features

- Autonomous LAN recon & mapping
- Advanced ARP, port, and service fingerprinting
- Real-time traffic tap & analysis
- Threat surface & rogue device detection
- Loot logging, summary, and analytics
- GhostScan: Outbound infrastructure detection
- Anomaly detection & live threat enrichment
- Session logging, reporting, and export
- WLAN beacon hunting
- (And a hell of a lot more...)

## Core Modules

| Module Name             | Description                                |
|-------------------------|--------------------------------------------|
$(ls modules/*.py | xargs -n1 basename | sed 's/\.py//' | awk '{printf "| %-23s | - |\n", $1}')
| ...more coming soon...  |                                            |

## CLI Usage

Each module can be called directly, e.g.:

```sh
lanimals recon
lanimals netmap
lanimals ghostscan
lanimals lootsummary
lanimals anomalydetector
lanimals threatenrich
lanimals sessionlogger
lanimals wlanbeacon
lanimals darkwebhost
# ...etc

