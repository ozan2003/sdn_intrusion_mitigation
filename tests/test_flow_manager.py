"""Tests for controller.flow_manager."""

from __future__ import annotations

from ipaddress import IPv4Address
from unittest.mock import MagicMock

from ryu.ofproto import ofproto_v1_3 as ofproto13
from ryu.ofproto import ofproto_v1_3_parser as parser13

from controller.flow_manager import (
    DEFAULT_HARD_TIMEOUT,
    MITIGATION_PRIORITY,
    FlowManager,
)


def _make_datapath(dpid: int = 1) -> MagicMock:
    dp = MagicMock()
    dp.id = dpid
    dp.ofproto = ofproto13
    dp.ofproto_parser = parser13
    return dp


class TestInstallDropRule:
    def test_sends_flow_mod_with_empty_instructions(self):
        dp = _make_datapath()
        fm = FlowManager()

        fm.install_drop_rule(dp, IPv4Address("10.0.1.10"))

        dp.send_msg.assert_called_once()
        msg = dp.send_msg.call_args[0][0]
        assert isinstance(msg, parser13.OFPFlowMod)
        assert msg.priority == MITIGATION_PRIORITY
        assert msg.instructions == []
        assert msg.hard_timeout == DEFAULT_HARD_TIMEOUT

    def test_match_includes_vlan_when_specified(self):
        dp = _make_datapath()
        fm = FlowManager()

        fm.install_drop_rule(dp, IPv4Address("10.0.1.10"), vlan_vid=15)

        msg = dp.send_msg.call_args[0][0]
        match_dict = dict(msg.match._fields2)
        assert ("vlan_vid", 15 | ofproto13.OFPVID_PRESENT) in (
            match_dict.items()
        )


class TestInstallRateLimit:
    def test_sends_meter_mod_then_flow_mod(self):
        dp = _make_datapath()
        fm = FlowManager()

        fm.install_rate_limit(dp, IPv4Address("10.0.1.10"), rate_kbps=256)

        assert dp.send_msg.call_count == 2
        meter_msg = dp.send_msg.call_args_list[0][0][0]
        flow_msg = dp.send_msg.call_args_list[1][0][0]

        assert isinstance(meter_msg, parser13.OFPMeterMod)
        assert meter_msg.command == ofproto13.OFPMC_ADD
        assert meter_msg.flags == ofproto13.OFPMF_KBPS

        assert isinstance(flow_msg, parser13.OFPFlowMod)
        assert flow_msg.priority == MITIGATION_PRIORITY

    def test_reuses_meter_id_for_same_ip(self):
        dp = _make_datapath()
        fm = FlowManager()

        fm.install_rate_limit(dp, IPv4Address("10.0.1.10"))
        first_meter = dp.send_msg.call_args_list[0][0][0]

        dp.reset_mock()
        fm.install_rate_limit(dp, IPv4Address("10.0.1.10"))
        second_meter = dp.send_msg.call_args_list[0][0][0]

        assert first_meter.meter_id == second_meter.meter_id


class TestRemoveMitigation:
    def test_sends_delete_flow_and_meter(self):
        dp = _make_datapath()
        fm = FlowManager()

        fm.install_rate_limit(dp, IPv4Address("10.0.1.10"))
        dp.reset_mock()

        fm.remove_mitigation(dp, IPv4Address("10.0.1.10"))

        assert dp.send_msg.call_count == 2
        flow_del = dp.send_msg.call_args_list[0][0][0]
        meter_del = dp.send_msg.call_args_list[1][0][0]

        assert isinstance(flow_del, parser13.OFPFlowMod)
        assert flow_del.command == ofproto13.OFPFC_DELETE_STRICT

        assert isinstance(meter_del, parser13.OFPMeterMod)
        assert meter_del.command == ofproto13.OFPMC_DELETE

    def test_skips_meter_delete_when_no_meter_exists(self):
        dp = _make_datapath()
        fm = FlowManager()

        fm.install_drop_rule(dp, IPv4Address("10.0.1.10"))
        dp.reset_mock()

        fm.remove_mitigation(dp, IPv4Address("10.0.1.10"))

        assert dp.send_msg.call_count == 1
        msg = dp.send_msg.call_args[0][0]
        assert isinstance(msg, parser13.OFPFlowMod)
