#!/usr/bin/env python3
from rich import print
from rich.panel import Panel


def show_threat_map():
    print(
        Panel.fit(
            "[bold red]192.168.1.141[/bold red]  Rogue AP Detected\n"
            "[bold yellow]192.168.1.175[/bold yellow]  Port Scan Activity\n"
            "[bold magenta]192.168.1.211[/bold magenta]  Unknown Service Response",
            title="LANIMALS :: ThreatMap",
            border_style="bold blue",
        )
    )


if __name__ == "__main__":
    show_threat_map()
