from __future__ import annotations

import sys

from core.nexus_scope import ScopeError, validate_host_target, validate_scan_cidr


def validate_target(value: str) -> str:
    if "/" in value:
        return validate_scan_cidr(value)
    return validate_host_target(value)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m core.validate_scope_cli HOST_OR_CIDR", file=sys.stderr)
        return 2
    try:
        print(validate_target(sys.argv[1]))
    except ScopeError as exc:
        print(f"scope rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
