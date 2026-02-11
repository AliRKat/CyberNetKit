from __future__ import annotations

import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class ScanResult:
    port: int
    state: PortState
    detail: Optional[str] = None  # e.g., error string


def scan_port(host: str, port: int, timeout: float) -> ScanResult:
    """
    TCP connect scan.
    - open: connect succeeds
    - closed: connection refused
    - timeout: connect timed out
    - error: other socket errors
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ScanResult(port=port, state=PortState.OPEN)
    except socket.timeout:
        return ScanResult(port=port, state=PortState.TIMEOUT)
    except ConnectionRefusedError:
        return ScanResult(port=port, state=PortState.CLOSED)
    except OSError as e:
        # covers host resolution issues, network unreachable, etc.
        return ScanResult(port=port, state=PortState.ERROR, detail=str(e))


def resolve_host(target: str) -> str:
    """
    Resolve hostname to an IP string for display.
    """
    try:
        return socket.gethostbyname(target)
    except OSError:
        return target

@dataclass(frozen=True)
class ScanResult:
    port: int
    state: PortState
    detail: Optional[str] = None
    banner: Optional[str] = None