import os
import shutil

print("[] Network Scan (Non-root fallback)")

if shutil.which("nmap"):
    print("[+] Running Nmap ping sweep...")
    os.system("nmap -sn 192.168.1.0/24")  # Change subnet if needed
else:
    print("[+] Falling back to ping sweep...")
    os.system("for ip in $(seq 1 254); do ping -c 1 -W 1 192.168.1.\$ip | grep 'ttl' & done; wait")
