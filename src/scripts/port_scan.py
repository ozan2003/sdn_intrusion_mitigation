#!/usr/bin/env python3
"""Run a TCP SYN port scan from a Mininet host namespace.

Example usage (from the Mininet CLI, project root as cwd):
    mininet> hacker .venv/bin/python3 src/scripts/port_scan.py 10.0.3.10 -s 10 -e 50000
"""

from __future__ import annotations

import argparse
import random
import time
from ipaddress import IPv4Address

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

# Default scan range used by CLI args when custom ports are not provided.
DEFAULT_SCAN_PORT_START = 1
DEFAULT_SCAN_PORT_END = 1024


def port_scan(
    target: IPv4Address,
    *,
    start_port: int = DEFAULT_SCAN_PORT_START,
    end_port: int = DEFAULT_SCAN_PORT_END,
) -> None:
    """Send one TCP SYN per port in [start_port, end_port] to target.

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

    print(f"[{FILE_NAME}] {target=} ports={start_port}..={end_port}")

    for port in range(start_port, end_port + 1):
        pkt = scapy.IP(dst=str(target)) / scapy.TCP(
            sport=random.randint(1024, 65535),  # noqa: S311
            dport=port,
            flags="S",
        )
        scapy.send(pkt, verbose=False)
        time.sleep(0.01)

    total = end_port - start_port + 1
    print(f"[{FILE_NAME}] done - {total} ports scanned")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate TCP SYN port-scan traffic.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", type=IPv4Address, help="Target IPv4 address")
    parser.add_argument(
        "-s",
        "--start-port",
        type=int,
        default=DEFAULT_SCAN_PORT_START,
        help="First port to scan",
    )
    parser.add_argument(
        "-e",
        "--end-port",
        type=int,
        default=DEFAULT_SCAN_PORT_END,
        help="Last port to scan",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    port_scan(args.target, start_port=args.start_port, end_port=args.end_port)


if __name__ == "__main__":
    main()
