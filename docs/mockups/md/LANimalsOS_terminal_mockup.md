# LANimalsOS terminal mockup

```shell
kali@redteam:~/LANimals$ ./lanimals-os.sh

╔════════════════════════════════════════════════════════════╗
║               LANimalsOS v1.0 – Terminal Recon Suite       ║
║ Interface  : wlan0                                         ║
║ Hostname   : kali                                          ║
║ Target Net : 192.168.0.0/24                                ║
║ Mode       : Passive Recon                                 ║
║ Theme      : Classic Black                                 ║
╚════════════════════════════════════════════════════════════╝

 [1] Start Network Recon
 [2] Launch Packet Sniffer
 [3] View Threat Map
 [4] Loot Vault
 [5] Change Theme
 [6] LANimals Quote of the Day
 [Q] Exit

> 1

[+] Initializing subnet scan on wlan0...
[+] Scanning 192.168.0.0/24...
[+] Passive ARP probe active...

[+] Devices Discovered: 12
------------------------------------------------------------
 IP Address     MAC Address        Hostname        OS Guess
------------------------------------------------------------
 192.168.0.1    AA:BB:CC:DD:01     gateway.local   OpenWRT
 192.168.0.2    F2:4D:6B:23:9A     nvr-cam         Linux
 192.168.0.5    3C:D9:2B:47:FA     tv_box          Android
 192.168.0.7    28:CF:E9:88:01     hp-printer      Embedded
 192.168.0.9    90:B6:86:72:1F     laptop-user     Windows 10
 ...            ...                ...             ...
------------------------------------------------------------

[+] Recon report saved: loot/session_20250605/recon.json

```
