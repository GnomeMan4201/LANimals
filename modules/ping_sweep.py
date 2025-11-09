import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
# LANimals :: Ping Sweep Module
# Author: NMAPKin

import ipaddress
import subprocess
import threading
from queue import Queue
from lanimals_utils import banner, print_status, log_event

THREADS = 100
ACTIVE = []

def ping_host(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)],
                                stdout=subprocess.DEVNULL)
        if result.returncode == 0:
            ACTIVE.append(str(ip))
            log_event(f"[ALIVE] {ip}")
    except Exception as e:
        print_status(f"Error pinging {ip}: {e}", "-")

def main():
    banner("LANimals :: Ping Sweep")
    subnet = input("Enter target subnet (e.g., 192.168.1.0/24): ")
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print_status("Invalid subnet", "✗")
        return

    q = Queue()
    for ip in net.hosts():
        q.put(ip)

    def worker():
        while not q.empty():
            ip = q.get()
            ping_host(ip)
            q.task_done()

    for _ in range(min(THREADS, q.qsize())):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

    q.join()
    print_status(f"Scan complete. {len(ACTIVE)} host(s) up.", "✓")

if __name__ == "__main__":
    main()
