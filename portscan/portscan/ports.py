from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PortParseError(Exception):
    message: str


def parse_ports(spec: str) -> list[int]:
    """
    Parse a port specification like:
      "22,80,443,8000-8100"

    Returns sorted unique ports.
    """
    spec = (spec or "").strip()
    if not spec:
        raise PortParseError("Port spec is empty")

    ports: set[int] = set()
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        raise PortParseError("Port spec is empty")

    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            a = a.strip()
            b = b.strip()
            if not a.isdigit() or not b.isdigit():
                raise PortParseError(f"Invalid range: '{part}'")
            start = int(a)
            end = int(b)
            if start > end:
                raise PortParseError(f"Range start > end: '{part}'")
            for p in range(start, end + 1):
                _validate_port(p, part)
                ports.add(p)
        else:
            if not part.isdigit():
                raise PortParseError(f"Invalid port: '{part}'")
            p = int(part)
            _validate_port(p, part)
            ports.add(p)

    return sorted(ports)


def _validate_port(p: int, ctx: str) -> None:
    if p < 1 or p > 65535:
        raise PortParseError(f"Port out of range (1-65535): '{ctx}'")
