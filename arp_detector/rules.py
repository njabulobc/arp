"""Detection rules and logic for ARP spoofing."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .binding_cache import BindingCache, BindingEntry
from .parser import ParsedARPPacket


@dataclass
class DetectionEvent:
    """Represents a detection decision."""

    severity: str
    reason: str
    packet: ParsedARPPacket
    binding: Optional[BindingEntry]
    occurrences: int


class RuleMatchingModule:
    """Apply heuristic rules to parsed ARP packets."""

    def __init__(self, cache: BindingCache) -> None:
        self.cache = cache

    def evaluate(self, packet: ParsedARPPacket) -> List[str]:
        reasons: List[str] = []
        if self.cache.detect_conflict(packet.sender_ip, packet.sender_mac):
            reasons.append(
                "Sender IP mapped to multiple MAC addresses"
            )
        if packet.operation == "reply" and packet.target_ip == packet.sender_ip:
            reasons.append("Gratuitous ARP reply detected")
        if packet.operation == "reply" and packet.target_mac == "00:00:00:00:00:00":
            reasons.append("ARP reply with empty target MAC")
        return reasons


class ThresholdEvaluator:
    """Aggregates rule matches and applies temporal thresholds."""

    def __init__(
        self,
        window_seconds: int = 120,
        detection_trigger: int = 3,
        high_trigger: Optional[int] = None,
        medium_trigger: int = 1,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.detection_trigger = detection_trigger
        self.high_trigger = high_trigger or detection_trigger
        self.medium_trigger = medium_trigger
        self._events: Dict[str, List[datetime]] = {}

    def register(self, key: str, timestamp: datetime) -> int:
        """Record a suspicious event and return the number of occurrences in the window."""
        occurrences = self._events.setdefault(key, [])
        occurrences.append(timestamp)
        self._events[key] = [ts for ts in occurrences if timestamp - ts <= self.window]
        return len(self._events[key])

    def severity_for(self, occurrences: int) -> str:
        if occurrences >= self.high_trigger:
            return "high"
        if occurrences >= self.medium_trigger:
            return "medium"
        return "low"

    def meets_detection_threshold(self, occurrences: int) -> bool:
        return occurrences >= self.detection_trigger


class DecisionLogic:
    """Combines rules and thresholds to emit detection events."""

    def __init__(self, cache: BindingCache, rules: RuleMatchingModule, thresholds: ThresholdEvaluator) -> None:
        self.cache = cache
        self.rules = rules
        self.thresholds = thresholds

    def process(self, packet: ParsedARPPacket) -> Optional[DetectionEvent]:
        reasons = self.rules.evaluate(packet)
        binding = self.cache.update(packet.sender_ip, packet.sender_mac)
        if not reasons:
            return None

        key = packet.sender_ip
        occurrences = self.thresholds.register(key, packet.timestamp)
        if not self.thresholds.meets_detection_threshold(occurrences):
            return None

        severity = self.thresholds.severity_for(occurrences)
        reason = "; ".join(reasons)

        return DetectionEvent(
            severity=severity,
            reason=reason,
            packet=packet,
            binding=binding,
            occurrences=occurrences,
        )
