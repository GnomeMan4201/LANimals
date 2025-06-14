#!/usr/bin/env python3
from rich.console import Console
from time import sleep
import random

ascii_arts = [
    r"   |\_/|     ",
    r"   (o o)     ",
    r"  ==_Y_==    ",
    r"    `-'      ",
    r"  HACK MODE  ",
]

def main():
    console = Console()
    console.clear()
    console.print("[bold magenta]LANIMALS :: ASCII ROTATOR[/bold magenta]")
    for _ in range(3):
        art = random.choice(ascii_arts)
        console.print(f"[bold green]{art}[/bold green]")
        sleep(1)

if __name__ == "__main__":
    main()
