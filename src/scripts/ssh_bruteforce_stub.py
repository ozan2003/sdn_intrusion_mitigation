#!/usr/bin/env python3
"""Run an SSH brute-force traffic-pattern stub from a Mininet host namespace.

This script does not perform credential guessing. It only generates repeated
TCP connection attempts to emulate brute-force cadence.

Example usage (from the Mininet CLI):
    mininet> hacker .venv/bin/python3 src/scripts/ssh_bruteforce_stub.py 10.0.3.10 -a 200 -r 10
"""

from __future__ import annotations

import argparse
import socket
import time
from ipaddress import IPv4Address

FILE_NAME = __file__.split("/")[-1]

# Default brute-force stub profile for demo traffic generation.
DEFAULT_SSH_PORT = 22
DEFAULT_ATTEMPTS = 200
DEFAULT_ATTEMPTS_PER_SECOND = 10
DEFAULT_CONNECT_TIMEOUT_SECONDS = 0.5


def ssh_bruteforce_stub(
    target: IPv4Address,
    *,
    destination_port: int = DEFAULT_SSH_PORT,
    attempts: int = DEFAULT_ATTEMPTS,
    attempts_per_second: int = DEFAULT_ATTEMPTS_PER_SECOND,
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
) -> None:
    """Generate repeated TCP connection attempts toward an SSH service.

    Args:
        target: Destination IPv4 address.
        destination_port: Destination TCP port (default SSH: 22).
        attempts: Number of connect attempts to perform.
        attempts_per_second: Connection attempt rate.
        connect_timeout_seconds: Per-attempt socket timeout.
    """
    if not 1 <= destination_port <= 65535:
        msg = "Destination port must be between 1 and 65535"
        raise ValueError(msg)
    if attempts <= 0:
        msg = "Attempts must be greater than 0"
        raise ValueError(msg)
    if attempts_per_second <= 0:
        msg = "Attempts per second must be greater than 0"
        raise ValueError(msg)
    if connect_timeout_seconds <= 0:
        msg = "Connect timeout must be greater than 0"
        raise ValueError(msg)

    interval = 1.0 / attempts_per_second
    successful_connects = 0
    failed_connects = 0

    print(
        f"[{FILE_NAME}] {target=} dport={destination_port} "
        f"{attempts=} {attempts_per_second=}"
    )

    for _ in range(attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(connect_timeout_seconds)
            result = sock.connect_ex((str(target), destination_port))
        if result == 0:
            successful_connects += 1
        else:
            failed_connects += 1
        time.sleep(interval)

    print(
        f"[{FILE_NAME}] done - {attempts=} "
        f"{successful_connects=} {failed_connects=}"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate SSH brute-force traffic pattern for SDN detection demo.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", type=IPv4Address, help="Target IPv4 address")
    parser.add_argument(
        "-P",
        "--destination-port",
        type=int,
        default=DEFAULT_SSH_PORT,
        help="Destination TCP port",
    )
    parser.add_argument(
        "-a",
        "--attempts",
        type=int,
        default=DEFAULT_ATTEMPTS,
        help="Total connection attempts",
    )
    parser.add_argument(
        "-r",
        "--attempts-per-second",
        type=int,
        default=DEFAULT_ATTEMPTS_PER_SECOND,
        help="Connection attempts per second",
    )
    parser.add_argument(
        "-t",
        "--connect-timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT_SECONDS,
        help="Connection timeout in seconds",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    ssh_bruteforce_stub(
        args.target,
        destination_port=args.destination_port,
        attempts=args.attempts,
        attempts_per_second=args.attempts_per_second,
        connect_timeout_seconds=args.connect_timeout,
    )


if __name__ == "__main__":
    main()
