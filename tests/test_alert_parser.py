"""Tests for controller.alert_parser."""

from __future__ import annotations

import json

import pytest

from controller.alert_parser import (
    ARP_SPOOFING_SID,
    HORIZONTAL_SCAN_SID,
    ICMP_FLOOD_SID,
    MAC_FLOODING_SID,
    PORT_SCAN_SID,
    SSH_BRUTE_FORCE_SID,
    SYN_FLOOD_SID,
    UDP_FLOOD_SID,
    AlertParser,
    MitigationAction,
)


def _eve_line(
    *,
    event_type: str = "alert",
    src_ip: str = "10.0.1.10",
    dest_ip: str = "10.0.3.10",
    src_port: int = 54321,
    dest_port: int = 80,
    proto: str = "TCP",
    sid: int = 1000001,
    signature: str = "THREAT SYN Flood Detected",
    severity: int = 2,
) -> str:
    obj = {
        "event_type": event_type,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "proto": proto,
        "alert": {
            "signature_id": sid,
            "signature": signature,
            "severity": severity,
        },
    }
    return json.dumps(obj)


class TestParseAlert:
    def test_syn_flood_alert_yields_rate_limit(self):
        line = _eve_line(sid=SYN_FLOOD_SID)
        alert = AlertParser._parse(line)

        assert alert is not None
        assert alert.action == MitigationAction.RATE_LIMIT
        assert alert.src_ip == "10.0.1.10"
        assert alert.dst_ip == "10.0.3.10"
        assert alert.signature_id == SYN_FLOOD_SID

    def test_port_scan_alert_yields_drop(self):
        line = _eve_line(
            sid=PORT_SCAN_SID,
            signature="THREAT Port Scan Detected",
        )
        alert = AlertParser._parse(line)

        assert alert is not None
        assert alert.action == MitigationAction.DROP
        assert alert.signature_id == PORT_SCAN_SID

    @pytest.mark.parametrize(
        ("sid", "action"),
        [
            (ICMP_FLOOD_SID, MitigationAction.RATE_LIMIT),
            (UDP_FLOOD_SID, MitigationAction.RATE_LIMIT),
            (HORIZONTAL_SCAN_SID, MitigationAction.DROP),
            (ARP_SPOOFING_SID, MitigationAction.DROP),
            (MAC_FLOODING_SID, MitigationAction.RATE_LIMIT),
            (SSH_BRUTE_FORCE_SID, MitigationAction.DROP),
        ],
    )
    def test_extended_sids_map_to_expected_actions(
        self, sid: int, action: MitigationAction
    ):
        line = _eve_line(sid=sid, signature=f"sid-{sid}")
        alert = AlertParser._parse(line)

        assert alert is not None
        assert alert.signature_id == sid
        assert alert.action == action

    def test_unknown_sid_returns_none(self):
        line = _eve_line(sid=9999999, signature="Unknown rule")
        alert = AlertParser._parse(line)

        assert alert is None

    def test_non_alert_event_returns_none(self):
        line = _eve_line(event_type="stats")
        alert = AlertParser._parse(line)

        assert alert is None

    def test_malformed_json_returns_none(self):
        alert = AlertParser._parse("{broken json,,,")

        assert alert is None

    def test_alert_fields_fully_populated(self):
        line = _eve_line(
            src_ip="192.168.1.1",
            dest_ip="10.0.3.20",
            src_port=12345,
            dest_port=443,
            proto="TCP",
            sid=1000001,
            signature="THREAT SYN Flood Detected",
            severity=1,
        )
        alert = AlertParser._parse(line)

        assert alert is not None
        assert alert.src_ip == "192.168.1.1"
        assert alert.dst_ip == "10.0.3.20"
        assert alert.src_port == 12345
        assert alert.dst_port == 443
        assert alert.proto == "TCP"
        assert alert.severity == 1
