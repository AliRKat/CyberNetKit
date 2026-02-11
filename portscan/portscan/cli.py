from __future__ import annotations

import argparse
from collections import Counter

from .ports import PortParseError, parse_ports
from .scanner import PortState, resolve_host, scan_port
from .banner import grab_banner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="portscan", description="TCP connect port scanner (demo v0.1)")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a target")
    scan.add_argument("target", help="IP or hostname")
    scan.add_argument("-p", "--ports", required=True, help="ports, e.g. 22,80,443,8000-8100")
    scan.add_argument("--timeout", type=float, default=0.5, help="connect timeout seconds (default: 0.5)")
    scan.add_argument("--show-closed", action="store_true", help="print closed ports too")
    scan.add_argument("--show-timeout", action="store_true", help="print timeout ports too")
    scan.add_argument("--show-error", action="store_true", help="print error ports too")
    scan.add_argument("--banner", action="store_true", help="best-effort banner grabbing on open ports")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "scan":
        try:
            ports = parse_ports(args.ports)
        except PortParseError as e:
            print(f"[!] {e.message}")
            return 2

        ip = resolve_host(args.target)
        print(f"{args.target} ({ip})")
        results = []
        for port in ports:
            r = scan_port(args.target, port, float(args.timeout))
            results.append(r)

            if r.state == PortState.OPEN:
                btxt = None
                if args.banner:
                    b = grab_banner(args.target, port, float(args.timeout))
                    if b:
                        if b.server:
                            btxt = f"{b.text} (Server: {b.server})"
                        else:
                            btxt = b.text

                if btxt:
                    print(f"  {port}/tcp  open     {btxt}")
                else:
                    print(f"  {port}/tcp  open")
            elif r.state == PortState.CLOSED and args.show_closed:
                print(f"  {port}/tcp  closed")
            elif r.state == PortState.TIMEOUT and args.show_timeout:
                print(f"  {port}/tcp  timeout")
            elif r.state == PortState.ERROR and args.show_error:
                detail = f" ({r.detail})" if r.detail else ""
                print(f"  {port}/tcp  error{detail}")

        counts = Counter(r.state.value for r in results)
        open_n = counts.get("open", 0)
        closed_n = counts.get("closed", 0)
        timeout_n = counts.get("timeout", 0)
        error_n = counts.get("error", 0)
        print(f"Summary: open={open_n} closed={closed_n} timeout={timeout_n} error={error_n}")
        return 0

    return 1
