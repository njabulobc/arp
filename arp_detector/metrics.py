"""Metrics collection for ARP monitoring."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class IncidentRecord:
    timestamp: datetime
    summary: str
    severity: str
    ip_address: str
    mac_address: str
    occurrences: int


@dataclass
class Metrics:
    total_packets: int = 0
    suspicious_packets: int = 0
    incidents: List[IncidentRecord] = field(default_factory=list)

    def record_packet(self) -> None:
        self.total_packets += 1

    def record_incident(self, incident: IncidentRecord) -> None:
        self.suspicious_packets += 1
        self.incidents.append(incident)
