#!/usr/bin/env python3
import random
from time import sleep

from rich.console import Console

console = Console()


def flicker_frame(text):
    for _ in range(8):
        glow = random.choice(["bold red", "bold green", "bold magenta", "bold yellow"])
        console.print(text, style=glow)
        sleep(0.2)
        console.clear()


if __name__ == "__main__":
    flicker_frame("LANIMALS :: VISUAL UPGRADE")
