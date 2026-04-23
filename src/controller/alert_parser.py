"""Parse Suricata EVE JSON alerts and classify mitigation actions."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ryu.lib import hub

if TYPE_CHECKING:
    from collections.abc import Callable

LOG = logging.getLogger(__name__)
# wrapper for static typing, we're guaranteeing that hub is imported
_hub = cast(Any, hub)

# Custom Suricata signature IDs defined in ids/rules/custom.rules.
SYN_FLOOD_SID = 1000001
PORT_SCAN_SID = 1000002
ICMP_FLOOD_SID = 1000003
UDP_FLOOD_SID = 1000004
HORIZONTAL_SCAN_SID = 1000005
ARP_SPOOFING_SID = 1000006
MAC_FLOODING_SID = 1000007
SSH_BRUTE_FORCE_SID = 1000008


class MitigationAction(Enum):
    """Action the controller should take for a detected threat."""

    DROP = "drop"
    RATE_LIMIT = "rate_limit"


_SID_ACTION_MAP: dict[int, MitigationAction] = {
    SYN_FLOOD_SID: MitigationAction.RATE_LIMIT,
    PORT_SCAN_SID: MitigationAction.DROP,
    ICMP_FLOOD_SID: MitigationAction.RATE_LIMIT,
    UDP_FLOOD_SID: MitigationAction.RATE_LIMIT,
    HORIZONTAL_SCAN_SID: MitigationAction.DROP,
    ARP_SPOOFING_SID: MitigationAction.DROP,
    MAC_FLOODING_SID: MitigationAction.RATE_LIMIT,
    SSH_BRUTE_FORCE_SID: MitigationAction.DROP,
}


@dataclass(frozen=True, slots=True)
class Alert:
    """Represents a Suricata alert."""

    src_ip: IPv4Address
    dst_ip: IPv4Address
    src_port: int
    dst_port: int
    proto: str
    signature_id: int
    signature: str
    severity: int
    action: MitigationAction


class AlertParser:
    """Tails Suricata's EVE JSON log and emits `Alert`s."""

    def __init__(self, eve_path: str | Path) -> None:
        self._eve_path = Path(eve_path)

    def watch(self, callback: Callable[[Alert], None]) -> None:
        """Blocks (greenthread-friendly) and tails *eve_path* for new alerts.

        Yields control via `hub.sleep` between poll cycles so the Ryu
        event loop is not starved.
        """
        while not self._eve_path.exists():
            LOG.info("Waiting for %s to appear ...", self._eve_path)
            _hub.sleep(2)

        with self._eve_path.open() as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    _hub.sleep(1)
                    continue
                alert = self._parse(line)
                if alert is not None:
                    callback(alert)

    @staticmethod
    def _parse(line: str) -> Alert | None:
        """Parse a single EVE JSON line; return `Alert` or `None`."""
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            LOG.warning("Malformed JSON line: %s", line[:120])
            return None

        if evt.get("event_type") != "alert":
            return None

        alert_data = evt.get("alert", {})
        sid = alert_data.get("signature_id", 0)
        mitigation = _SID_ACTION_MAP.get(sid)
        if mitigation is None:
            return None

        return Alert(
            src_ip=evt.get("src_ip", ""),
            dst_ip=evt.get("dest_ip", ""),
            src_port=evt.get("src_port", 0),
            dst_port=evt.get("dest_port", 0),
            proto=evt.get("proto", ""),
            signature_id=sid,
            signature=alert_data.get("signature", ""),
            severity=alert_data.get("severity", 0),
            action=mitigation,
        )
