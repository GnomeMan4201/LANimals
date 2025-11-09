import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

def show_banner():
    return '''
██╗      █████╗ ███╗   ██╗██╗███╗   ███╗ █████╗ ██╗     
██║     ██╔══██╗████╗  ██║██║████╗ ████║██╔══██╗██║     
██║     ███████║██╔██╗ ██║██║██╔████╔██║███████║██║     
██║     ██╔══██║██║╚██╗██║██║██║╚██╔╝██║██╔══██║██║     
███████╗██║  ██║██║ ╚████║██║██║ ╚═╝ ██║██║  ██║███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
                TRIPWIRE MONITOR
'''

def main():
    console = Console()
    console.print(Panel(show_banner(), style="cyan"))
    tw_path = Path.home() / ".lanimals" / "data" / "tripwire.log"
    if tw_path.exists():
        console.print(f"[bold green][ OK ][/bold green] Monitoring for tripwire hits ({datetime.now()})\n")
        for line in tw_path.read_text().splitlines()[-20:]:
            console.print(line)
    else:
        console.print("[bold red][ WARN ][/bold red] No tripwire activity detected.")
    console.print("\n[bold green][ OK ][/bold green] Tripwire check complete.\n")

if __name__ == "__main__":
    main()
