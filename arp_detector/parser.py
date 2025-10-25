"""Packet parsing utilities."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from scapy.layers.l2 import ARP
from scapy.packet import Packet


@dataclass
class ParsedARPPacket:
    """Normalized representation of an ARP packet."""

    operation: str
    sender_ip: str
    sender_mac: str
    target_ip: str
    target_mac: str
    timestamp: datetime
    raw: Dict[str, Any]
    is_attack: Optional[bool] = None
    label: Optional[str] = None


class PacketParser:
    """Parse Scapy packets into internal representations."""

    @staticmethod
    def parse(packet: Packet) -> ParsedARPPacket:
        if not packet.haslayer(ARP):
            raise ValueError("Packet is not an ARP frame")

        arp_layer: ARP = packet[ARP]
        operation = "request" if arp_layer.op == 1 else "reply" if arp_layer.op == 2 else str(arp_layer.op)
        return ParsedARPPacket(
            operation=operation,
            sender_ip=arp_layer.psrc,
            sender_mac=arp_layer.hwsrc,
            target_ip=arp_layer.pdst,
            target_mac=arp_layer.hwdst,
            timestamp=datetime.utcnow(),
            raw={
                "hwtype": arp_layer.hwtype,
                "ptype": arp_layer.ptype,
                "hwlen": arp_layer.hwlen,
                "plen": arp_layer.plen,
                "op": arp_layer.op,
            },
        )
