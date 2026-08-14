from __future__ import annotations

import ipaddress
import os
import socket
from typing import Iterable


class ScopeError(ValueError):
    """Raised when a requested scan target is outside the approved LAN scope."""


def _rfc1918_networks() -> tuple[ipaddress.IPv4Network, ...]:
    return (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )


def _is_rfc1918(network: ipaddress.IPv4Network) -> bool:
    return any(network.subnet_of(private) for private in _rfc1918_networks())


def _parse_networks(values: Iterable[str]) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for raw in values:
        value = raw.strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopeError(f"invalid approved CIDR: {value}") from exc
        if not isinstance(network, ipaddress.IPv4Network) or not _is_rfc1918(network):
            raise ScopeError(f"approved CIDR must be an RFC1918 IPv4 network: {value}")
        networks.append(network)
    return networks


def _detected_local_networks() -> list[ipaddress.IPv4Network]:
    try:
        import psutil
    except Exception:
        return []

    networks: set[ipaddress.IPv4Network] = set()
    for iface, addresses in psutil.net_if_addrs().items():
        if iface.lower().startswith((
            "docker", "veth", "virbr", "br-", "lxc", "lxd", "vbox",
            "vmnet", "tun", "tap", "wg", "utun",
        )):
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            try:
                network = ipaddress.ip_interface(
                    f"{address.address}/{address.netmask}"
                ).network
            except ValueError:
                continue
            if _is_rfc1918(network):
                networks.add(network)
    return sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen))


def detected_local_networks() -> list[ipaddress.IPv4Network]:
    """Return a copy of eligible, non-virtual RFC1918 interface networks."""
    return list(_detected_local_networks())


def approved_networks() -> list[ipaddress.IPv4Network]:
    configured = os.environ.get("LANIMALS_ALLOWED_CIDRS", "")
    if configured.strip():
        return _parse_networks(configured.split(","))
    return detected_local_networks()


def default_scan_cidr() -> str:
    limit = _max_scan_addresses()
    for network in approved_networks():
        if network.num_addresses <= limit:
            return str(network)
    raise ScopeError(
        "no detected LAN scope fits the scan-size limit; set "
        "LANIMALS_ALLOWED_CIDRS to an explicit subnet"
    )


def scope_summary() -> dict[str, object]:
    networks = approved_networks()
    try:
        default = default_scan_cidr()
    except ScopeError:
        default = None
    return {
        "approved_cidrs": [str(item) for item in networks],
        "default_cidr": default,
        "max_scan_addresses": _max_scan_addresses(),
    }


def _max_scan_addresses() -> int:
    raw = os.environ.get("LANIMALS_MAX_SCAN_ADDRESSES", "4096")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ScopeError("LANIMALS_MAX_SCAN_ADDRESSES must be an integer") from exc
    if value < 1 or value > 65536:
        raise ScopeError("LANIMALS_MAX_SCAN_ADDRESSES must be between 1 and 65536")
    return value


def validate_scan_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ScopeError(f"invalid scan CIDR: {value}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ScopeError("LANimals currently supports IPv4 LAN scans only")
    if not _is_rfc1918(network):
        raise ScopeError("scan CIDR must be inside an RFC1918 private network")
    if network.num_addresses > _max_scan_addresses():
        raise ScopeError(
            f"scan CIDR contains {network.num_addresses} addresses; configured limit is "
            f"{_max_scan_addresses()}"
        )
    allowed = approved_networks()
    if not allowed:
        raise ScopeError(
            "no approved LAN scope detected; set LANIMALS_ALLOWED_CIDRS explicitly"
        )
    if not any(network.subnet_of(parent) for parent in allowed):
        rendered = ", ".join(str(item) for item in allowed)
        raise ScopeError(f"scan CIDR is outside the approved LAN scope: {rendered}")
    return str(network)


def validate_host_target(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ScopeError(f"invalid host target: {value}") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ScopeError("LANimals currently supports IPv4 LAN targets only")
    allowed = approved_networks()
    if not allowed:
        raise ScopeError(
            "no approved LAN scope detected; set LANIMALS_ALLOWED_CIDRS explicitly"
        )
    if not any(address in network for network in allowed):
        rendered = ", ".join(str(item) for item in allowed)
        raise ScopeError(f"host target is outside the approved LAN scope: {rendered}")
    if any(
        address in network
        and address in {network.network_address, network.broadcast_address}
        for network in allowed
    ):
        raise ScopeError("host target cannot be a network or broadcast address")
    return str(address)
