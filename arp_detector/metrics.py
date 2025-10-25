"""Metrics collection for ARP monitoring."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from statistics import mean
from typing import List, Optional

from .parser import ParsedARPPacket


@dataclass
class IncidentRecord:
    timestamp: datetime
    summary: str
    severity: str
    ip_address: str
    mac_address: str
    occurrences: int


@dataclass
class ResourceSnapshot:
    """A single resource usage sample captured during monitoring."""

    timestamp: datetime
    cpu_percent: float
    bandwidth_bytes_per_sec: float


@dataclass
class Metrics:
    """Aggregates operational and effectiveness metrics."""

    total_packets: int = 0
    suspicious_packets: int = 0
    incidents: List[IncidentRecord] = field(default_factory=list)
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    _resource_samples: List[ResourceSnapshot] = field(default_factory=list)

    def record_packet(self, packet: ParsedARPPacket, snapshot: Optional[ResourceSnapshot] = None) -> None:
        """Register that a packet has been processed."""

        self.total_packets += 1
        if snapshot:
            self._resource_samples.append(snapshot)

    def record_incident(self, incident: IncidentRecord) -> None:
        self.suspicious_packets += 1
        self.incidents.append(incident)

    def evaluate_detection(self, is_attack: Optional[bool], detected: bool) -> None:
        """Update effectiveness counters when ground truth is available."""

        if is_attack is None:
            return

        if is_attack and detected:
            self.true_positive += 1
        elif is_attack and not detected:
            self.false_negative += 1
        elif not is_attack and detected:
            self.false_positive += 1
        else:
            self.true_negative += 1

    @property
    def evaluation_total(self) -> int:
        return self.true_positive + self.true_negative + self.false_positive + self.false_negative

    @property
    def accuracy(self) -> float:
        total = self.evaluation_total
        if total == 0:
            return 0.0
        return (self.true_positive + self.true_negative) / total

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positive + self.true_negative
        if denominator == 0:
            return 0.0
        return self.false_positive / denominator

    @property
    def detection_rate(self) -> float:
        denominator = self.true_positive + self.false_negative
        if denominator == 0:
            return 0.0
        return self.true_positive / denominator

    @property
    def average_cpu(self) -> float:
        if not self._resource_samples:
            return 0.0
        return mean(sample.cpu_percent for sample in self._resource_samples)

    @property
    def average_bandwidth(self) -> float:
        if not self._resource_samples:
            return 0.0
        return mean(sample.bandwidth_bytes_per_sec for sample in self._resource_samples)

    def snapshot(self) -> dict[str, object]:
        """Return a serialisable representation of current metrics."""

        return {
            "total_packets": self.total_packets,
            "suspicious_packets": self.suspicious_packets,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "accuracy": self.accuracy,
            "false_positive_rate": self.false_positive_rate,
            "detection_rate": self.detection_rate,
            "average_cpu": self.average_cpu,
            "average_bandwidth": self.average_bandwidth,
            "incidents": [
                {
                    "timestamp": incident.timestamp.isoformat(),
                    "summary": incident.summary,
                    "severity": incident.severity,
                    "ip_address": incident.ip_address,
                    "mac_address": incident.mac_address,
                    "occurrences": incident.occurrences,
                }
                for incident in self.incidents
            ],
        }
