from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Banner:
    text: str
    server: Optional[str] = None


def grab_banner(host: str, port: int, timeout: float) -> Optional[Banner]:
    """
    Best-effort banner grabbing:
    - SSH: read initial banner line
    - HTTP: send HEAD / and read headers, try to extract Server:
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)

            # Try SSH banner first (servers usually send it immediately)
            try:
                peek = s.recv(128)
                if peek:
                    txt = _safe_decode(peek).strip()
                    if txt.startswith("SSH-"):
                        # SSH banner might include extra bytes; keep first line
                        line = txt.splitlines()[0].strip()
                        return Banner(text=line)
            except socket.timeout:
                pass

            # Try HTTP HEAD
            req = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            try:
                s.sendall(req)
                data = s.recv(2048)
                if not data:
                    return None
                txt = _safe_decode(data)
                # First line + Server header (if present)
                first_line = txt.split("\r\n", 1)[0].strip()
                server = _extract_server_header(txt)
                if first_line.startswith("HTTP/"):
                    return Banner(text=first_line, server=server)
            except (socket.timeout, OSError):
                return None

    except (socket.timeout, OSError):
        return None

    return None


def _extract_server_header(http_text: str) -> Optional[str]:
    for line in http_text.split("\r\n"):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip() or None
    return None


def _safe_decode(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")
