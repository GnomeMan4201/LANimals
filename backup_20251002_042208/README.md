<p align="center">
  <img src="assets/LANimals.png" alt="LANimals Banner" width="600">
</p>

# LANimals

A interactive LAN situational awareness & threat hunting toolkit for hackers, blue teams, and security pros.

---

## Features

- **Native ASCII CLI dashboards and mapping**
- **Real time network/host recon, alerting, and anomaly detection**
- **Modular command suite—see below!**
- **Unique, gritty style with serious capabilities**

---

## Command Overview


| Command                       | Description                               |
|-------------------------------|-------------------------------------------|
| `lanimals_dash`               | Show LANimals dashboard                   |
| `lanimals_sysinfo`            | Analyze system components                 |
| `lanimals_sessionLogger`      | Session logger/report generator           |
| `lanimals_recon`              | Autonomous recon                          |
| `lanimals_traffic`            | Analyze network traffic                   |
| `lanimals_netmap`             | Map network devices visually              |
| `lanimals_viznet`             | Interactive network visualization         |
| `lanimals_wlanbeacon`         | WLAN beacon hunter                        |
| `lanimals_fortress`           | Security hardening toolkit                |
| `lanimals_alert`              | Run threat alert system                   |
| `lanimals_vulscan`            | Network vulnerability scanner             |
| `lanimals_roguescan`          | Scan for rogue devices                    |
| `lanimals_ghostscan`          | Outbound infra detection                  |
| `lanimals_darkwebhost`        | Dark web host detector                    |
| `lanimals_threatenrich`       | Live threat intel enrichment              |
| `lanimals_anomalydetector`    | Network anomaly detector                  |
| `lanimals_Lootlog`            | View loot log entries                     |
| `lanimals_lootsummary`        | Loot analytics/summarizer                 |
| `lanimals_tripwire`           | Monitor tripwire events                   |
| `lanimals_asciiroll`          | Show rotating ASCII banners               |
| `help`                        | Show this help message                    |
| `version`                     | Show LANimals version                     |
| `update`                      | Check for updates                         |

*LANimals: Running inside Termux for Android*

---

## Screenshots

### Threat Alerting in Action
<p align="center">
  <img src="assets/lanimals_demo2.png" alt="LANimals Threat Alert Demo" width="700">
</p>
<p align="center"><i>LANimals: Real time threat alert pop-up in action</i></p>

### ASCII Subnet Mapping
<p align="center">
  <img src="assets/lanimals_demo3.png" alt="LANimals Subnet Mapping Demo" width="700">
</p>
<p align="center"><i>LANimals: Native-style network mapper with ASCII subnet layout</i></p>

### Termux CLI in Action
<p align="center">
  <img src="assets/lanimals_termux_demo.png" alt="LANimals Termux Demo" width="700">
</p>
<p align="center"><i>LANimals: Running on Android/Termux with full dashboard</i></p>

---

## Why LANimals is Unique

- Native ASCII dashboards—classic hacker feel
- Menu driven and modular (pick your tool or run them all)
- Designed for real-world recon, threat hunting, blue/red team ops
- Works seamlessly on Kali, Linux, and Termux for Android

---

## Quick Start

```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
pip install -r requirements.txt
./lanimals_dash
