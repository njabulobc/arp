"""High level ARP monitoring controller."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from PyQt5.QtCore import QObject, pyqtSignal
from scapy.all import AsyncSniffer, get_if_list
from scapy.layers.l2 import ARP

from .binding_cache import BindingCache
from .event_logger import EventLogger
from .metrics import IncidentRecord, Metrics
from .parser import PacketParser, ParsedARPPacket
from .rules import DecisionLogic, DetectionEvent, RuleMatchingModule, ThresholdEvaluator


@dataclass
class MonitorConfig:
    interface: Optional[str]
    window_seconds: int
    trigger_threshold: int


class ARPMonitor(QObject):
    """Coordinates packet capture and analysis."""

    packet_processed = pyqtSignal(ParsedARPPacket)
    incident_detected = pyqtSignal(DetectionEvent)
    log_generated = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.cache = BindingCache()
        self.logger = EventLogger()
        self.metrics = Metrics()
        self.thresholds = ThresholdEvaluator()
        self.rules = RuleMatchingModule(self.cache)
        self.decision = DecisionLogic(self.cache, self.rules, self.thresholds)
        self.sniffer: Optional[AsyncSniffer] = None
        self._config: Optional[MonitorConfig] = None

    def available_interfaces(self) -> list[str]:
        return get_if_list()

    def configure(self, config: MonitorConfig) -> None:
        self._config = config
        self.thresholds = ThresholdEvaluator(config.window_seconds, config.trigger_threshold)
        self.decision = DecisionLogic(self.cache, self.rules, self.thresholds)
        self.log_generated.emit(
            f"Configured monitor: interface={config.interface or 'all'}, window={config.window_seconds}s, trigger={config.trigger_threshold}"
        )

    def start(self) -> None:
        if self.sniffer and self.sniffer.running:
            return
        iface = self._config.interface if self._config else None
        self.sniffer = AsyncSniffer(iface=iface, filter="arp", prn=self._handle_packet, store=False)
        self.sniffer.start()
        self.log_generated.emit("ARP monitor started")

    def stop(self) -> None:
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.sniffer = None
            self.log_generated.emit("ARP monitor stopped")

    def _handle_packet(self, packet) -> None:
        if not packet.haslayer(ARP):
            return
        parsed = PacketParser.parse(packet)
        self.metrics.record_packet()
        self.packet_processed.emit(parsed)
        detection = self.decision.process(parsed)
        if detection:
            self.metrics.record_incident(
                IncidentRecord(
                    timestamp=parsed.timestamp,
                    summary=detection.reason,
                    severity=detection.severity,
                    ip_address=parsed.sender_ip,
                    mac_address=parsed.sender_mac,
                    occurrences=detection.occurrences,
                )
            )
            self.incident_detected.emit(detection)
            message = (
                f"[{detection.severity.upper()}] {parsed.sender_ip} -> {parsed.target_ip} | {detection.reason}"
            )
            self.logger.log(message)
            self.log_generated.emit(message)

    def reset(self) -> None:
        self.cache = BindingCache()
        self.logger.clear()
        self.metrics = Metrics()
        self.thresholds = ThresholdEvaluator()
        self.rules = RuleMatchingModule(self.cache)
        self.decision = DecisionLogic(self.cache, self.rules, self.thresholds)
        self.log_generated.emit("Monitor state reset")
