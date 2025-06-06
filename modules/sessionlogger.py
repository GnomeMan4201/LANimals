#!/usr/bin/env python3
import os
import datetime
import socket
import platform
from rich import print

REPORT_DIR = os.path.expanduser("~/.lanimals/reports/")
os.makedirs(REPORT_DIR, exist_ok=True)

def get_sysinfo():
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "user": os.environ.get("USER") or os.getlogin(),
        "datetime": str(datetime.datetime.now()),
    }

def main():
    print("[bold red]\nLANimals Session Logger / Report Generator\n[/bold red]")
    info = get_sysinfo()
    session_file = os.path.join(REPORT_DIR, f"session_{info['datetime'].replace(' ','_').replace(':','-')}.txt")
    with open(session_file, "w") as f:
        for k, v in info.items():
            f.write(f"{k}: {v}\n")
    print(f"[green][ OK ] Session info saved: {session_file}\n[/green]")

if __name__ == "__main__":
    main()
