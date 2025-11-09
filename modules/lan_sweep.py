import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import os
def main():
    print("\n[✓] Running LAN Sweep...")
    os.system("ip r | grep -oP '(?<=src )\\d+\\.\\d+\\.\\d+\\.\\d+' | head -n1 | awk -F. '{print $1\".\"$2\".\"$3\".0/24\"}' > /data/data/com.termux/files/usr/tmp/target_net")
    with open('/data/data/com.termux/files/usr/tmp/target_net') as f:
        subnet = f.read().strip()
    os.system(f"nmap -sn {subnet} -oG - | grep Up")
if __name__ == "__main__":
    main()
