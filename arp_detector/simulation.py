"""Traffic simulation utilities for effectiveness evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List

from .monitor import ARPMonitor
from .parser import ParsedARPPacket


@dataclass
class TrafficScenario:
    """Represents a controlled traffic pattern with ground truth."""

    name: str
    packets: List[ParsedARPPacket]


class TrafficSimulator:
    """Feed synthetic packets into a monitor for evaluation."""

    def __init__(self, scenarios: Iterable[TrafficScenario]) -> None:
        self.scenarios = list(scenarios)

    @staticmethod
    def default_scenario() -> "TrafficSimulator":
        base_time = datetime.utcnow()
        packets: List[ParsedARPPacket] = []

        # Baseline traffic
        for index in range(10):
            packets.append(
                ParsedARPPacket(
                    operation="reply",
                    sender_ip=f"192.168.1.{index+2}",
                    sender_mac=f"aa:bb:cc:dd:ee:{index:02x}",
                    target_ip="192.168.1.1",
                    target_mac="ff:ff:ff:ff:ff:ff",
                    vlan=None,
                    timestamp=base_time + timedelta(seconds=index),
                    raw={},
                    is_attack=False,
                    label="baseline",
                )
            )

        # Spoofing burst
        attacker_mac = "de:ad:be:ef:00:01"
        target_ip = "192.168.1.5"
        for offset in range(5):
            packets.append(
                ParsedARPPacket(
                    operation="reply",
                    sender_ip=target_ip,
                    sender_mac=attacker_mac,
                    target_ip="192.168.1.1",
                    target_mac="ff:ff:ff:ff:ff:ff",
                    vlan=None,
                    timestamp=base_time + timedelta(seconds=20 + offset),
                    raw={},
                    is_attack=True,
                    label="spoof",
                )
            )

        scenario = TrafficScenario(name="baseline_spoof_mix", packets=packets)
        return TrafficSimulator([scenario])

    def run(self, monitor: ARPMonitor) -> None:
        for scenario in self.scenarios:
            for packet in scenario.packets:
                monitor.ingest_simulated_packet(packet)
