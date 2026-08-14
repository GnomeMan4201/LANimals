from __future__ import annotations

import shlex
from dataclasses import dataclass


class TerminalCommandError(ValueError):
    """Raised when the browser command bridge receives an unsupported command."""


@dataclass(frozen=True)
class TerminalCommand:
    action: str
    target: str | None = None


_SIMPLE_COMMANDS = {
    "help", "clear", "status", "hosts", "events", "baseline", "sysinfo", "report"
}
_SCAN_COMMANDS = {"arp", "discovery", "hostmap", "rogue", "services", "cve"}


def simple_commands() -> set[str]:
    """Return a copy of the supported non-scan browser commands."""
    return set(_SIMPLE_COMMANDS)


def scan_commands() -> set[str]:
    """Return a copy of the supported browser scan operations."""
    return set(_SCAN_COMMANDS)


def parse_terminal_command(raw: str) -> TerminalCommand:
    try:
        parts = shlex.split(raw.strip())
    except ValueError as exc:
        raise TerminalCommandError(str(exc)) from exc
    if parts and parts[0].lower() == "lanimals":
        parts = parts[1:]
    if not parts:
        return TerminalCommand("help")

    command = parts[0].lower()
    if command in _SIMPLE_COMMANDS:
        if len(parts) != 1:
            raise TerminalCommandError(f"{command} does not accept arguments")
        return TerminalCommand(command)

    if command != "scan":
        raise TerminalCommandError(
            "unsupported command; type 'help' for the allowlisted command set"
        )
    if len(parts) < 2 or parts[1].lower() not in _SCAN_COMMANDS:
        raise TerminalCommandError(
            "usage: scan <arp|discovery|hostmap|rogue|services|cve> [target]"
        )

    operation = parts[1].lower()
    target = parts[2] if len(parts) == 3 else None
    if len(parts) > 3:
        raise TerminalCommandError("scan accepts at most one target")
    if operation in {"services", "cve"} and not target:
        raise TerminalCommandError(f"scan {operation} requires an IPv4 target")
    return TerminalCommand(f"scan:{operation}", target)


def terminal_help() -> list[str]:
    return [
        "LANimals operator command bridge",
        "  status                     show persistent datastore counts",
        "  hosts                      list observed hosts",
        "  events                     show recent events",
        "  baseline                   show unresolved identity changes",
        "  sysinfo                    show local system inventory",
        "  scan arp [CIDR]            refresh ARP observations in approved scope",
        "  scan discovery [CIDR]      run bounded LAN discovery",
        "  scan hostmap [CIDR]        resolve hosts in approved scope",
        "  scan rogue [CIDR]          compare observations to baseline",
        "  scan services <IPv4>       fingerprint one approved host",
        "  scan cve <IPv4>            run nmap vulners on one approved host",
        "  report                     show the local report endpoint",
        "  clear                      clear this terminal",
        "",
        "This bridge does not expose a system shell.",
    ]
