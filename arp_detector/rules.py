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

    def __init__(self, window_seconds: int = 120, trigger: int = 3) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.trigger = trigger
        self._events: Dict[str, List[datetime]] = {}

    def register(self, key: str, timestamp: datetime) -> int:
        """Record a suspicious event and return the number of occurrences in the window."""
        occurrences = self._events.setdefault(key, [])
        occurrences.append(timestamp)
        self._events[key] = [ts for ts in occurrences if timestamp - ts <= self.window]
        return len(self._events[key])

    def exceeds_threshold(self, key: str) -> bool:
        timestamps = self._events.get(key)
        if not timestamps:
            return False
        now = datetime.utcnow()
        timestamps[:] = [ts for ts in timestamps if now - ts <= self.window]
        return len(timestamps) >= self.trigger


class DecisionLogic:
    """Combines rules and thresholds to emit detection events."""

    def __init__(self, cache: BindingCache, rules: RuleMatchingModule, thresholds: ThresholdEvaluator) -> None:
        self.cache = cache
        self.rules = rules
        self.thresholds = thresholds

    def process(self, packet: ParsedARPPacket) -> Optional[DetectionEvent]:
        binding = self.cache.update(packet.sender_ip, packet.sender_mac)
        reasons = self.rules.evaluate(packet)
        if not reasons:
            return None

        key = packet.sender_ip
        occurrences = self.thresholds.register(key, packet.timestamp)
        severity = "high" if self.thresholds.exceeds_threshold(key) else "medium"
        reason = "; ".join(reasons)

        return DetectionEvent(
            severity=severity,
            reason=reason,
            packet=packet,
            binding=binding,
            occurrences=occurrences,
        )
