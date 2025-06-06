![LANimals Logo](assets/lanimals_logo.png)

---


### System Info
![SysInfo](assets/sysinfo.png)

### Threat Intel
![Threat](assets/threat1.png)

### Traffic Capture
![Traffic](assets/traffic1.png)

### Network Mapping
![NetMap](assets/netmap1.png)


---

## [ PHILOSOPHY ]
<p align="center">
LANimals transforms the operator into a predator of the local network — silently observing, tagging, probing, and documenting prey systems in real time with zero setup.  
Everything from interface scans, MAC spoofing, ARP hunts, and stealth probes — in a clean, stylized suite.
</p>

---

## [ FEATURES ]
<p align="center">

- Interface & ARP Scanning  
- Intelligent Loot Logging  
- Fast Ping Sweeps + Alive Reports  
- Mass Port Scanner  
- Drop Decoy Artifacts  
- HTTP Header Probe  
- Self-Diagnostic System  
- Python-based CLI, no external setup  
- LAN-aware modular UX  

</p>

---

## [ MODULES ]
<p align="center">

| Module                 | Description                                         |
|------------------------|-----------------------------------------------------|
| `interface_scan.py`    | Scans interfaces & shows MAC/IP info                |
| `arp_hunter.py`        | Probes the LAN with raw ARP requests                |
| `ping_sweep.py`        | Fast subnet ping to find alive hosts                |
| `alive_report.py`      | Generates timestamped alive-host reports            |
| `mass_scan.py`         | Nmap scanner across all live targets                |
| `loot_log.py`          | Operator notes & findings logged with timestamp     |
| `loot_viewer.py`       | View stored loot collected in ops                   |
| `http_probe.py`        | Retrieves HTTP response headers from a target URL   |
| `lanimals-launcher.py` | CLI control center for all modules                  |
| `lanimals-check.py`    | Self-diagnostic script to verify tool integrity     |

</p>

---

## [ QUICKSTART ]

```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
python3 main.py


## [ QUICKSTART ]

## [ MOCKUPS ]

> Preview terminal-style walkthroughs of LANimals in action:

- [LANimalsOS Terminal UI](docs/mockups/LANimalsOS_terminal_mockup.txt)
- [Threatmap Visualizer](docs/mockups/LANimalsOS_threatmap_mockup.txt)
