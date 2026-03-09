"""OpenFlow 1.3 rule management for threat mitigation on s1_omurga."""

from __future__ import annotations

import logging
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, Any

from ryu.ofproto import ofproto_v1_3 as ofproto13
from ryu.ofproto import ofproto_v1_3_parser as parser13

if TYPE_CHECKING:
    from ryu.controller.controller import Datapath

LOG = logging.getLogger(__name__)

MITIGATION_PRIORITY = 100
DEFAULT_HARD_TIMEOUT = 300  # seconds


class FlowManager:
    """Install / remove drop and rate-limit rules on a datapath."""

    def __init__(self) -> None:
        self._meter_ids: dict[int, dict[IPv4Address, int]] = {}
        self._next_meter_id: int = 1

    def add_flow(
        self,
        datapath: Datapath,
        priority: int,
        match: parser13.OFPMatch,
        instructions: list,
        *,
        idle_timeout: int = 0,
        hard_timeout: int = 0,
        table_id: int = 0,
    ) -> None:
        """Sends a generic `OFPFlowMod` ADD to *datapath*."""
        mod = parser13.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            table_id=table_id,
        )
        datapath.send_msg(mod)

    def install_drop_rule(
        self,
        datapath: Datapath,
        src_ip: IPv4Address,
        *,
        hard_timeout: int = DEFAULT_HARD_TIMEOUT,
        vlan_vid: int | None = None,
    ) -> None:
        """Installs a high-priority flow that drops all traffic from *src_ip*.

        Args:
            datapath: Target OVS datapath.
            src_ip: Attacker IPv4 address to block.
            hard_timeout: Seconds before the rule auto-expires.
            vlan_vid: Optional VLAN to scope the rule to a specific zone.
        """
        match_fields: dict[str, Any] = {
            "eth_type": 0x0800,
            "ipv4_src": src_ip,
        }
        if vlan_vid is not None:
            match_fields["vlan_vid"] = vlan_vid | ofproto13.OFPVID_PRESENT

        match = parser13.OFPMatch(**match_fields)
        self.add_flow(
            datapath,
            priority=MITIGATION_PRIORITY,
            match=match,
            instructions=[],
            hard_timeout=hard_timeout,
        )
        LOG.warning(
            "DROP rule installed on dpid=%s for src_ip=%s "
            "(vlan=%s, timeout=%ds)",
            datapath.id,
            src_ip,
            vlan_vid,
            hard_timeout,
        )

    def install_rate_limit(
        self,
        datapath: Datapath,
        src_ip: IPv4Address,
        *,
        rate_kbps: int = 512,
        hard_timeout: int = DEFAULT_HARD_TIMEOUT,
        vlan_vid: int | None = None,
    ) -> None:
        """Rate-limits traffic from *src_ip* using an OpenFlow meter.

        Creates a meter with a DROP band at *rate_kbps*, then installs a
        flow that sends matching packets through that meter before
        continuing to table processing.
        """
        if datapath.id is None:
            msg = "Datapath ID is not set"
            raise RuntimeError(msg)

        meter_id = self._allocate_meter_id(datapath.id, src_ip)

        bands = [
            parser13.OFPMeterBandDrop(
                rate=rate_kbps,
                burst_size=rate_kbps * 2,
            ),
        ]
        meter_mod = parser13.OFPMeterMod(
            datapath=datapath,
            command=ofproto13.OFPMC_ADD,
            flags=ofproto13.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands,
        )
        datapath.send_msg(meter_mod)

        match_fields: dict[str, Any] = {
            "eth_type": 0x0800,
            "ipv4_src": src_ip,
        }
        if vlan_vid is not None:
            match_fields["vlan_vid"] = vlan_vid | ofproto13.OFPVID_PRESENT

        match = parser13.OFPMatch(**match_fields)
        instructions = [
            parser13.OFPInstructionMeter(meter_id=meter_id),
            parser13.OFPInstructionGotoTable(table_id=0),
        ]
        self.add_flow(
            datapath,
            priority=MITIGATION_PRIORITY,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout,
        )
        LOG.warning(
            "RATE-LIMIT rule installed on dpid=%s for src_ip=%s "
            "(meter=%d, %d kbps, vlan=%s, timeout=%ds)",
            datapath.id,
            src_ip,
            meter_id,
            rate_kbps,
            vlan_vid,
            hard_timeout,
        )

    def remove_mitigation(
        self,
        datapath: Datapath,
        src_ip: IPv4Address,
        *,
        vlan_vid: int | None = None,
    ) -> None:
        """Removes a previously installed drop or rate-limit rule."""
        match_fields: dict[str, Any] = {
            "eth_type": 0x0800,
            "ipv4_src": src_ip,
        }
        if vlan_vid is not None:
            match_fields["vlan_vid"] = vlan_vid | ofproto13.OFPVID_PRESENT

        match = parser13.OFPMatch(**match_fields)
        mod = parser13.OFPFlowMod(
            datapath=datapath,
            command=ofproto13.OFPFC_DELETE_STRICT,
            priority=MITIGATION_PRIORITY,
            match=match,
            out_port=ofproto13.OFPP_ANY,
            out_group=ofproto13.OFPG_ANY,
            instructions=[],
        )
        datapath.send_msg(mod)

        if datapath.id is None:
            msg = "Datapath ID is not set"
            raise RuntimeError(msg)

        meter_id = self._release_meter_id(datapath.id, src_ip)
        if meter_id is not None:
            meter_del = parser13.OFPMeterMod(
                datapath=datapath,
                command=ofproto13.OFPMC_DELETE,
                meter_id=meter_id,
            )
            datapath.send_msg(meter_del)

        LOG.info(
            "Mitigation removed on dpid=%s for src_ip=%s",
            datapath.id,
            src_ip,
        )

    def _allocate_meter_id(self, dpid: int, src_ip: IPv4Address) -> int:
        dp_meters: dict[IPv4Address, int] = self._meter_ids.setdefault(
            dpid, {}
        )
        if src_ip in dp_meters:
            return dp_meters[src_ip]
        mid = self._next_meter_id
        self._next_meter_id += 1
        dp_meters[src_ip] = mid
        return mid

    def _release_meter_id(self, dpid: int, src_ip: IPv4Address) -> int | None:
        dp_meters = self._meter_ids.get(dpid, {})
        return dp_meters.pop(src_ip, None)
