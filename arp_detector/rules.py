"""Detection rules and logic for ARP spoofing."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional

from .binding_cache import BindingCache, BindingEntry
from .parser import ParsedARPPacket
from .signatures import SignatureMatcher


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

    def __init__(
        self,
        cache: BindingCache,
        *,
        rate_window_seconds: int = 5,
        rate_threshold: int = 20,
    ) -> None:
        self.cache = cache
        self._rate_window = timedelta(seconds=rate_window_seconds)
        self._rate_threshold = rate_threshold
        self._rate_events: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._signature_matcher = SignatureMatcher()

    def evaluate(self, packet: ParsedARPPacket) -> List[str]:
        reasons: List[str] = []
        vlan = packet.vlan
        if self.cache.detect_conflict(packet.sender_ip, packet.sender_mac, vlan):
            context = f" within VLAN {vlan}" if vlan is not None else ""
            reasons.append(
                "Sender IP mapped to multiple MAC addresses" + context
            )
        if self.cache.detect_vlan_conflict(packet.sender_ip, vlan):
            known = self.cache.get(packet.sender_ip)
            known_vlan = known.vlan if known else None
            reasons.append(
                f"VLAN mismatch for {packet.sender_ip}: observed {vlan}, expected {known_vlan}"
            )
        if packet.operation == "reply" and packet.target_ip == packet.sender_ip:
            reasons.append("Gratuitous ARP reply detected")
        if packet.operation == "reply" and packet.target_mac == "00:00:00:00:00:00":
            reasons.append("ARP reply with empty target MAC")
        lease_mac = self.cache.dhcp_mac_for(packet.sender_ip)
        if lease_mac and lease_mac.lower() != packet.sender_mac.lower():
            reasons.append(
                f"DHCP lease for {packet.sender_ip} maps to {lease_mac} but observed {packet.sender_mac}"
            )
        lease_vlan = self.cache.dhcp_vlan_for(packet.sender_ip)
        if lease_vlan is not None and vlan is not None and lease_vlan != vlan:
            reasons.append(
                f"Observed VLAN {vlan} conflicts with DHCP lease VLAN {lease_vlan}"
            )
        if self._is_rate_anomalous(packet):
            reasons.append(
                f"Rate anomaly: {packet.sender_ip} sent >= {self._rate_threshold} ARP replies in {self._rate_window.seconds}s"
            )
        signatures = self._signature_matcher.match(packet)
        for signature in signatures:
            reasons.append(f"Signature match: {signature}")
        return reasons

    def _is_rate_anomalous(self, packet: ParsedARPPacket) -> bool:
        if packet.operation != "reply":
            return False
        key = packet.sender_ip
        queue = self._rate_events[key]
        queue.append(packet.timestamp)
        cutoff = packet.timestamp - self._rate_window
        while queue and queue[0] < cutoff:
            queue.popleft()
        return len(queue) >= self._rate_threshold


class ThresholdEvaluator:
    """Aggregates rule matches and applies adaptive thresholds."""

    def __init__(
        self,
        window_seconds: int = 120,
        detection_trigger: int = 3,
        high_trigger: Optional[int] = None,
        medium_trigger: int = 1,
        baseline_alpha: float = 0.3,
        baseline_multiplier: float = 2.0,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.detection_trigger = detection_trigger
        self.high_trigger = high_trigger or detection_trigger
        self.medium_trigger = medium_trigger
        self.baseline_alpha = baseline_alpha
        self.baseline_multiplier = baseline_multiplier
        self._events: Dict[str, List[datetime]] = {}
        self._baselines: Dict[str, float] = {}
        self._asset_weights: Dict[str, float] = {}
        self._historical_counts: Dict[str, int] = {}

    def register(self, key: str, timestamp: datetime) -> int:
        """Record a suspicious event and return the number of occurrences in the window."""

        occurrences = self._events.setdefault(key, [])
        occurrences.append(timestamp)
        self._events[key] = [ts for ts in occurrences if timestamp - ts <= self.window]
        current = len(self._events[key])
        baseline = self._baselines.get(key)
        if baseline is None:
            self._baselines[key] = float(current)
        else:
            self._baselines[key] = (1 - self.baseline_alpha) * baseline + self.baseline_alpha * current
        return current

    def set_asset_weight(self, key: str, weight: float) -> None:
        self._asset_weights[key] = max(0.1, weight)

    def severity_for(self, key: str, occurrences: int) -> str:
        weight = self._asset_weights.get(key, 1.0)
        adjusted_high = max(1, int(round(self.high_trigger / weight)))
        adjusted_medium = max(1, int(round(self.medium_trigger / weight)))
        if occurrences >= adjusted_high:
            return "high"
        if occurrences >= adjusted_medium:
            return "medium"
        return "low"

    def meets_detection_threshold(self, key: str, occurrences: int) -> bool:
        weight = self._asset_weights.get(key, 1.0)
        dynamic_threshold = max(1, int(round(self.detection_trigger / weight)))
        if occurrences >= dynamic_threshold:
            return True
        baseline = self._baselines.get(key, 0.0)
        if baseline and occurrences >= baseline * self.baseline_multiplier:
            return True
        historical = self._historical_counts.get(key, 0)
        if historical > 0 and occurrences >= max(1, dynamic_threshold - 1):
            return True
        return False

    def record_detection(self, key: str) -> None:
        self._historical_counts[key] = self._historical_counts.get(key, 0) + 1


class DecisionLogic:
    """Combines rules and thresholds to emit detection events."""

    def __init__(self, cache: BindingCache, rules: RuleMatchingModule, thresholds: ThresholdEvaluator) -> None:
        self.cache = cache
        self.rules = rules
        self.thresholds = thresholds

    def process(self, packet: ParsedARPPacket) -> Optional[DetectionEvent]:
        reasons = self.rules.evaluate(packet)
        binding = self.cache.update(packet.sender_ip, packet.sender_mac, packet.vlan)
        self.thresholds.set_asset_weight(packet.sender_ip, binding.sensitivity)
        if not reasons:
            return None

        key = packet.sender_ip
        occurrences = self.thresholds.register(key, packet.timestamp)
        if not self.thresholds.meets_detection_threshold(key, occurrences):
            return None

        severity = self.thresholds.severity_for(key, occurrences)
        reason = "; ".join(reasons)

        self.thresholds.record_detection(key)
        return DetectionEvent(
            severity=severity,
            reason=reason,
            packet=packet,
            binding=binding,
            occurrences=occurrences,
        )
