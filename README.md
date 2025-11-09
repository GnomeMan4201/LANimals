![LANimals Logo](.github/branding/logo.png)

![Tests](https://github.com/GnomeMan4201/LANimals/workflows/Tests/badge.svg) ![Python](https://img.shields.io/badge/python-3.8+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Stars](https://img.shields.io/github/stars/GnomeMan4201/LANimals?style=social)


![LANimals Demo](.github/branding/demo.png)

# LANimals — Real-time Network Intelligence Suite

[![Security](https://img.shields.io/badge/Security-Audited-green.svg)](SECURITY.md)
[![License](https://img.shields.io/badge/license-GPL--3.0-lightgrey?style=flat)](LICENSE)
[![Language](https://img.shields.io/github/languages/top/GnomeMan4201/LANimals?style=flat)](https://github.com/GnomeMan4201/LANimals)
[![Last Commit](https://img.shields.io/github/last-commit/GnomeMan4201/LANimals?style=flat)](https://github.com/GnomeMan4201/LANimals/commits/main)

---

## summary
LANimals is a lightweight, production-oriented network reconnaissance suite for real-time device discovery, fingerprinting, and intelligence on local networks.

---

## Quick Start
> Run LANimals only on networks you own or have explicit permission to test.

### Option 1: Global Installation (Recommended)

Install LANimals as a global command to use it anywhere in your terminal:

```bash
# Clone the repository
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals

# Install globally (system-wide)
sudo pip install -e .

# Or install for current user only
pip install --user -e .
```

Now you can use LANimals from anywhere:

```bash
# All of these commands work from any directory
LANimals help
LANimals recon
lanimals scan
LANIMALS loot
```

### Option 2: Quick Start Script

For a quick demo without global installation:

```bash
# Clone the repo
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals

# Run the automated quickstart
./quickstart.sh
```

> The quickstart.sh script will create a virtual environment, install dependencies, and run a demo scan on a safe local subnet.

---

## Command-Line Interface

Once installed globally, LANimals provides a comprehensive CLI with multiple commands:

```bash
# View all available commands
LANimals help

# Common commands
LANimals recon              # Run ARP reconnaissance
LANimals ping-sweep         # Perform ping sweep across subnet
LANimals scan               # Run network port scan
LANimals loot               # View collected data
LANimals watchdog           # Monitor network for changes
LANimals ui                 # Launch web interface

# The command name is case-insensitive
lanimals recon              # Works the same
LANIMALS recon              # Also works
```

### Available Command Categories

- **Reconnaissance**: recon, arp-recon, arp-hunter, ping-sweep, lan-sweep
- **Scanning**: scan, net-scan, mass-scan, inventory-scan, interface-scan, ghostscan, roguescan
- **Analysis**: host-mapper, netmap, http-probe, service-fingerprint, sysinfo
- **Reporting**: loot, loot-viewer, loot-log, loot-export, loot-summary, alive-report
- **Monitoring**: watchdog, tripwire, traffic-tap, anomaly-detector, session-logger
- **Advanced**: autopilot, fortress, timeline, threat-enrich
- **Wireless**: wlan-beacon
- **Visualization**: ui, ascii

---

Highlights & Use Cases

Key capabilities

Host discovery across IPv4 local ranges (ARP, ICMP, and TCP probes)

Device categorization (printers, routers, cameras, workstations, IoT)

Service and OS fingerprinting with confidence scores

Live visualization dashboard (local web UI) and exportable reports (JSON/CSV)

Lightweight agent mode for constrained devices


Practical use cases

Rapid internal reconnaissance for incident response and validation

Asset inventory for small office / lab networks

Red team reconnaissance in permitted engagements (laboratory/target scope)

Defensive testing to tune IDS/endpoint detection rules



---

## Example Workflows

### Basic Network Reconnaissance

```bash
# Quick ARP scan of local network
LANimals recon

# Comprehensive ping sweep
LANimals ping-sweep

# Full network scan
LANimals scan

# View discovered devices and data
LANimals loot
```

### Advanced Scanning

```bash
# Stealthy scanning
LANimals ghostscan

# Mass network scanning
LANimals mass-scan

# Service fingerprinting
LANimals service-fingerprint

# Generate network map
LANimals netmap
```

### Monitoring and Defense

```bash
# Monitor network for changes
LANimals watchdog

# Detect anomalies
LANimals anomaly-detector

# Set up tripwire monitoring
LANimals tripwire

# Monitor traffic
LANimals traffic-tap
```

### Reporting and Visualization

```bash
# View loot summary
LANimals loot-summary

# Export data
LANimals loot-export

# Launch web UI
LANimals ui

# Generate alive hosts report
LANimals alive-report
```

---

Architecture (high-level)

LANimals/
├─ docs/                  # Design notes, API docs, visualization docs
├─ src/
│  ├─ lanimals/
│  │  ├─ scan.py          # Discovery engine
│  │  ├─ fingerprint.py   # Device/service classification logic
│  │  ├─ reporters.py     # JSON/CSV exporters and summaries
│  │  ├─ ui.py            # Lightweight web UI for visualization
│  │  └─ agent.py         # Constrained-host agent logic
├─ examples/              # Example configs & demo scripts
├─ tests/                 # Unit & integration tests
├─ configs/               # Default scan/report configs
└─ README.md

Design principles

Modular discovery engine — plug in new probes without changing core flow

Deterministic fingerprint scoring — combine network, protocol, and metadata signals into explainable confidence levels

Minimal external dependencies — suitable for single-board computers and VM-based labs



---

Configuration

Default configs live in configs/. Example config options:

probe types (ARP, ICMP, TCP)

timeout and retry settings

output formats (JSON, CSV)

fingerprint confidence thresholds


Place custom configs in configs/ or pass --config path/to/config.yml.


---

## Installation & Development

### For End Users

**Global Installation (Recommended):**

```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
sudo pip install -e .
```

After installation, you can use LANimals from any directory:

```bash
LANimals help
LANimals recon
```

**Uninstall:**

```bash
pip uninstall lanimals
```

### For Developers

1. Clone and set up development environment:

```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install in development mode:

```bash
pip install -e .
```

3. Install development dependencies:

```bash
pip install -r requirements.txt
```

4. Run the test suite:

```bash
pytest -q
```

5. Run linters and formatters:

```bash
./run_quality.sh
```

---

Security & Responsible Use

LANimals is intended for authorized testing, research, and defensive validation only.
Do not run scans against networks you do not own or have explicit permission to test.
See SECURITY.md for responsible disclosure and reporting procedures.


---

Contributing & Code of Conduct

Contributions are welcome:

Open issues for feature requests or bugs (include logs and minimal repro steps)

PRs should include tests or rationale for research/experimental code

Maintain backward compatibility and document breaking changes

Follow CODE_OF_CONDUCT.md


Suggested repo files: CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md.


---

Tests & CI

CI runs unit tests and integration checks

Add tests for new fingerprinting heuristics and reporters

Example datasets in tests/fixtures/ ensure deterministic results



---

License

GPL-3.0 — See LICENSE


---

Contact & Support

For collaboration, responsible disclosure, or professional inquiries:

Open an issue or use repository Discussions for non-sensitive questions

For private security reports, follow SECURITY.md instructions



---

Roadmap / Next Improvements

Agent telemetry with secure upload & ephemeral keys

Improved heuristics for IoT device families (cameras, thermostats, smart appliances)

Integration with local SIEM / log forwarders

Expand tests and add CI performance benchmarks
