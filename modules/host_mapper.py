import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import os
def main():
    print("\n[✓] Mapping hostnames on LAN...")
    os.system("nmap -sn 192.168.1.0/24 -oG - | awk '/Up/ {print \$2}' | while read ip; do host \$ip; done")
if __name__ == "__main__":
    main()
