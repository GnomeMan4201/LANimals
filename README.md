 <p align="center">
  <img src="docs/assets/LANIMALS_LOGO.png" alt="LANimals Logo" width="300"/>
</p>    <strong>Advanced Network Security & Monitoring Toolkit</strong>
  <br><br>

  <!-- Badges will go here once set up -->
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](./VERSION)
  [![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://github.com/GnomeMan4201/LANimals/graphs/commit-activity)
</div>

##Overview

LANimals is a comprehensive network security and monitoring toolkit designed for security professionals, system administrators, and network enthusiasts. It provides a powerful set of tools for analyzing, visualizing, and securing local networks with an intuitive command-line interface.                                                                                                                                                                            

 # LANimals   
 
### 
![Threat Hunter](docs/screenshots/originals/threat1.png)

LANimals is a network reconnaissance, security auditing, and monitoring toolkit built to automate LAN mapping, traffic analysis, system hardening, and threat detection from a unified command center. Designed for Kali Linux and other security-focused distributions.

### 
![Network Map](docs/screenshots/originals/netmap1.png)

## Features

- Network reconnaissance and device discovery
- System and service analysis
- Continuous LAN monitoring and threat alerts
- Traffic capture and protocol analysis
- Security auditing with recommendations
- Visual network mapping with ASCII art

## Installation

### From Source
```bash
git clone https://github.com/GnomeMan4201/LANimals.git
cd LANimals
sudo apt install dos2unix    # One-time install (required!)
dos2unix bin/*               # Fix line endings if needed
sudo make install
