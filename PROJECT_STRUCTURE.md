# LANimals Project Structure

**Version:** 1.0.0
**Date:** November 9, 2025
**Status:** Active Development

## Project Overview

LANimals is a lightweight, production-oriented network reconnaissance suite for real-time device discovery, fingerprinting, and intelligence on local networks. The project is organized into modular components for scanning, visualization, and advanced network analysis.

---

## Directory Structure

```
LANimals/
├── README.md                    # Main project documentation
├── LICENSE                      # GPL-3.0 license
├── VERSION                      # Current version (1.0.0)
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup configuration
├── pyproject.toml              # Modern Python packaging config
├── Makefile                     # Build and development tasks
├── .gitignore                   # Git ignore patterns
├── .flake8                      # Linting configuration
├── .pre-commit-config.yaml      # Pre-commit hooks
│
├── LANimals.py                  # Main CLI entry point
├── lanimals-ui.py              # UI launcher
├── fortress_menu.py            # Fortress defense module menu
├── quickstart.sh               # Quick setup script
├── install.sh                  # Installation script
├── run_quality.sh              # Code quality checks
│
├── LANimals/                    # Empty package directory
│
├── modules/                     # Core scanning and analysis modules
│   ├── __init__.py
│   ├── arp_recon.py            # ARP-based reconnaissance
│   ├── arp_hunter.py           # Advanced ARP hunting
│   ├── ping_sweep.py           # ICMP ping sweep scanner
│   ├── lan_sweep.py            # LAN discovery sweep
│   ├── net_scan.py             # General network scanning
│   ├── mass_scan.py            # Large-scale network scanning
│   ├── interface_scan.py       # Network interface enumeration
│   ├── host_mapper.py          # Host topology mapping
│   ├── netmap.py               # Network mapping utilities
│   │
│   ├── service_fingerprint.py  # Service identification
│   ├── http_probe.py           # HTTP service probing
│   ├── inventory_scan.py       # Device inventory management
│   ├── sysinfo.py              # System information gathering
│   │
│   ├── ghostscan.py            # Stealth scanning module
│   ├── roguescan.py            # Rogue device detection
│   ├── wlanbeacon.py           # WLAN beacon monitoring
│   ├── fortress.py             # Defense module
│   │
│   ├── anomalydetector.py      # Network anomaly detection
│   ├── tripwire_monitor.py     # Network change monitoring
│   ├── traffic_tap.py          # Traffic analysis
│   │
│   ├── threatenrich.py         # Threat intelligence enrichment
│   ├── darkwebhost.py          # Dark web host detection
│   │
│   ├── loot_log.py             # Scan results logging
│   ├── loot_viewer.py          # Results viewer
│   ├── loot_export.py          # Export functionality
│   ├── lootsummary.py          # Summary generation
│   │
│   ├── alive_report.py         # Live host reporting
│   ├── sessionlogger.py        # Session activity logging
│   ├── asciiroll.py            # ASCII art utilities
│   ├── autopilot.py            # Automated scanning
│
├── core/                        # Core framework components
│   ├── __init__.py
│   │
│   ├── lanimals_cli.py         # CLI framework
│   ├── lanimals_autopilot.py   # Autopilot orchestration
│   ├── lanimals_watchdog.py    # System watchdog
│   ├── lanimals_netmap.py      # Network mapping core
│   ├── lanimals_timeline.py    # Timeline visualization
│   │
│   ├── killchain.py            # Attack chain analysis
│   ├── exploit_fetcher.py      # Exploit database integration
│   ├── exploitlink.py          # Exploit linking
│   │
│   ├── dependency_scanner.py   # Dependency analysis
│   ├── osv_scanner.py          # OSV vulnerability scanner
│   ├── cache_osv.py            # OSV cache management
│   ├── ecosystem_guesser.py    # Technology detection
│   │
│   ├── nmap_parser.py          # Nmap output parser
│   │
│   ├── advanced/               # Advanced analysis modules
│   │   ├── lanimals_arpwatcher.py     # ARP monitoring
│   │   ├── lanimals_autopilot.py      # Advanced autopilot
│   │   ├── lanimals_cvehunt.py        # CVE hunting
│   │   ├── lanimals_dnstap.py         # DNS traffic analysis
│   │   ├── lanimals_ghostscan.py      # Stealth scanning
│   │   ├── lanimals_linkmap.py        # Link layer mapping
│   │   ├── lanimals_roguescan.py      # Advanced rogue detection
│   │   ├── lanimals_ssidhunter.py     # SSID discovery
│   │   ├── lanimals_stealthscan.py    # Stealth techniques
│   │   ├── lanimals_timeline.py       # Event timeline
│   │   ├── lanimals_watchdog.py       # Advanced monitoring
│   │   └── patch_lanimals_ui_visuals.sh  # UI patching script
│   │
│   └── visuals/                # Visualization components
│       ├── ascii_rotate.py     # ASCII animation
│       ├── asciiroll.py        # ASCII scrolling
│       ├── dashboard.py        # Main dashboard
│       ├── dashboard_ui.py     # Dashboard UI elements
│       ├── glow_frame.py       # Visual effects
│       ├── loot_counter.py     # Results counter
│       ├── lootcount.py        # Loot counting
│       └── threatmap.py        # Threat visualization
│
├── tests/                       # Test suite
│   ├── __init__.py
│   └── test_LANimals.py        # Main test file
│
├── docs/                        # Documentation
│   ├── index.html              # Documentation homepage
│   ├── .nojekyll               # GitHub Pages config
│   ├── LANIMALS_REPO_MANIFEST.txt  # Repository manifest
│   ├── assets/                 # Documentation assets
│   ├── mockups/                # UI/UX mockups
│   │   └── md/                 # Markdown mockups
│   └── screenshots/            # Application screenshots
│       └── originals/          # Original screenshots
│
├── reports/                     # Scan reports output directory
│
├── bin/                         # Binary/script executables
│
├── assets/                      # Project assets
│
├── build/                       # Build artifacts
│   └── lib/                    # Built library files
│       ├── core/
│       └── modules/
│
├── backup_*                     # Backup directories (4 backups)
│
└── venv/                        # Python virtual environment
    ├── bin/                    # Executables
    ├── lib/                    # Installed packages
    └── share/                  # Shared resources
```

---

## Key Components

### Entry Points

1. **LANimals.py** - Main CLI interface
   - Commands: `recon`, `scan`, `loot`
   - Routes to appropriate modules

2. **lanimals-ui.py** - Web UI launcher
   - Starts Flask-based visualization dashboard

3. **fortress_menu.py** - Defense module menu
   - Interactive menu for fortress/defense modules
   - Options: Rogue Scanner, ARP Watcher, Stealth Scanner

### Module Organization

#### Scanning Modules (`modules/`)
- **Discovery**: `arp_recon.py`, `ping_sweep.py`, `lan_sweep.py`, `net_scan.py`
- **Analysis**: `service_fingerprint.py`, `http_probe.py`, `inventory_scan.py`
- **Stealth**: `ghostscan.py`, `roguescan.py`
- **Monitoring**: `anomalydetector.py`, `tripwire_monitor.py`, `traffic_tap.py`
- **Reporting**: `loot_log.py`, `loot_viewer.py`, `loot_export.py`, `lootsummary.py`

#### Core Framework (`core/`)
- **CLI**: `lanimals_cli.py`, `lanimals_autopilot.py`
- **Analysis**: `killchain.py`, `exploit_fetcher.py`
- **Security**: `osv_scanner.py`, `dependency_scanner.py`, `cache_osv.py`
- **Visualization**: `lanimals_netmap.py`, `lanimals_timeline.py`

#### Advanced Features (`core/advanced/`)
- **Monitoring**: `lanimals_arpwatcher.py`, `lanimals_watchdog.py`
- **Detection**: `lanimals_cvehunt.py`, `lanimals_roguescan.py`
- **Wireless**: `lanimals_ssidhunter.py`
- **Stealth**: `lanimals_ghostscan.py`, `lanimals_stealthscan.py`

#### Visualization (`core/visuals/`)
- **Dashboards**: `dashboard.py`, `dashboard_ui.py`
- **Effects**: `ascii_rotate.py`, `asciiroll.py`, `glow_frame.py`
- **Metrics**: `loot_counter.py`, `threatmap.py`

---

## Dependencies

### Required Python Packages
- **psutil** - System and process utilities
- **faker** - Test data generation
- **colorama** - Terminal color support
- **requests** - HTTP library
- **rich** - Terminal formatting and UI
- **flask** - Web framework for UI
- **scapy** - Packet manipulation

### Installation
```bash
pip install -r requirements.txt
```

---

## Development Tools

### Setup Scripts
- `install.sh` - Full installation
- `quickstart.sh` - Quick setup and demo
- `run_quality.sh` - Code quality checks

### Configuration Files
- `.flake8` - Linting rules
- `.pre-commit-config.yaml` - Git hooks
- `pyproject.toml` - Python packaging
- `Makefile` - Build tasks

---

## Build Artifacts

### Build Directory Structure
```
build/
└── lib/
    ├── core/       # Compiled core modules
    └── modules/    # Compiled scanning modules
```

---

## Module API Patterns

### Standard Module Structure
Most modules follow this pattern:

```python
#!/usr/bin/env python3

def main():
    """Main execution function"""
    # Module-specific logic
    pass

def run():
    """Entry point for CLI integration"""
    # Called from LANimals.py
    pass

if __name__ == "__main__":
    main()
```

### Module Categories

1. **Discovery Modules**
   - Network scanning
   - Host enumeration
   - Service detection

2. **Analysis Modules**
   - Fingerprinting
   - Vulnerability detection
   - Threat enrichment

3. **Defense Modules**
   - Rogue detection
   - Anomaly detection
   - Monitoring

4. **Reporting Modules**
   - Data export
   - Visualization
   - Logging

---

## Testing

### Test Structure
- `tests/test_LANimals.py` - Main test suite
- Auto-generated pytest framework
- Tests for import validation and structure

### Running Tests
```bash
pytest tests/ -v
```

---

## Documentation

### Documentation Structure
- `docs/index.html` - Main documentation page
- `docs/LANIMALS_REPO_MANIFEST.txt` - Complete file listing
- `docs/screenshots/` - Application screenshots
- `docs/mockups/` - Design mockups

---

## Version Control

### Git Configuration
- `.gitignore` - Excludes `venv/`, `__pycache__/`, reports, etc.
- Pre-commit hooks for code quality
- Multiple backup directories preserved

---

## Usage Examples

### Basic Scanning
```bash
# Run ARP reconnaissance
python LANimals.py recon

# Run network scan
python LANimals.py scan

# View results
python LANimals.py loot
```

### Advanced Features
```bash
# Launch fortress menu
python fortress_menu.py

# Start web UI
python lanimals-ui.py
```

### Module-Specific
```bash
# Ping sweep
python -m modules.ping_sweep

# Ghost scan
python -m modules.ghostscan

# Anomaly detection
python -m modules.anomalydetector
```

---

## Architecture Notes

### Design Principles
1. **Modular Design** - Each module is independent and pluggable
2. **Minimal Dependencies** - Lightweight for constrained environments
3. **CLI-First** - Terminal-based operation with optional web UI
4. **Extensible** - Easy to add new scanning/analysis modules

### Key Patterns
- **Scan-Report-Export** workflow
- **Module discovery** via `__init__.py`
- **Lazy loading** for performance
- **Threaded scanning** for efficiency

---

## Security Considerations

### Responsible Use
- LANimals is for **authorized testing only**
- Includes stealth and evasion capabilities
- Threat intelligence integration
- Vulnerability scanning features

### Code Analysis Note
This project includes network reconnaissance and penetration testing tools. It should be used responsibly and only on networks you own or have explicit permission to test. See `SECURITY.md` for responsible disclosure procedures.

---

## Maintenance

### Backups
Multiple backup directories exist:
- `backup_20251002_042208/`
- `backup_20251002_043126/`
- `backup_20251002_121831/`
- `backup_20251002_122151/`

### Build Process
Build artifacts are stored in `build/lib/` and mirror the `core/` and `modules/` structure.

---

## Future Development

Based on README roadmap:
1. Agent telemetry with secure upload
2. Enhanced IoT device fingerprinting
3. SIEM integration
4. Performance benchmarks in CI

---

## Contact & Contributing

- License: GPL-3.0 (see LICENSE file)
- Version: 1.0.0
- Repository: https://github.com/GnomeMan4201/LANimals
- Issues: GitHub Issues
- Security: See SECURITY.md

---

*Document Generated: November 9, 2025*
*For: LANimals v1.0.0*
