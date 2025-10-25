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
from .notifications import NotificationManager, NotificationPolicy
from .resource_monitor import ResourceMonitor
from .parser import PacketParser, ParsedARPPacket
from .rules import DecisionLogic, DetectionEvent, RuleMatchingModule, ThresholdEvaluator


@dataclass
class MonitorConfig:
    interface: Optional[str]
    window_seconds: int
    detection_threshold: int
    high_severity_threshold: int
    alert_warning_threshold: int = 1
    alert_critical_threshold: int = 3


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
        self.resources = ResourceMonitor()
        self.notifications: Optional[NotificationManager] = None
        self.sniffer: Optional[AsyncSniffer] = None
        self._config: Optional[MonitorConfig] = None

    def available_interfaces(self) -> list[str]:
        return get_if_list()

    def configure(self, config: MonitorConfig) -> None:
        self._config = config
        self.thresholds = ThresholdEvaluator(
            window_seconds=config.window_seconds,
            detection_trigger=config.detection_threshold,
            high_trigger=config.high_severity_threshold,
        )
        self.decision = DecisionLogic(self.cache, self.rules, self.thresholds)
        self.resources.set_interface(config.interface)
        if self.notifications:
            policy = NotificationPolicy(
                warning_threshold=config.alert_warning_threshold,
                critical_threshold=config.alert_critical_threshold,
            )
            self.notifications.configure(policy)
        self.log_generated.emit(
            "Configured monitor: interface="
            f"{config.interface or 'all'}, window={config.window_seconds}s, "
            f"detect>={config.detection_threshold}, high>={config.high_severity_threshold}, "
            f"alert warn>={config.alert_warning_threshold}, critical>={config.alert_critical_threshold}"
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
        self.process_parsed_packet(parsed)

    def process_parsed_packet(self, packet: ParsedARPPacket) -> None:
        snapshot = self.resources.sample()
        self.metrics.record_packet(packet, snapshot)
        self.packet_processed.emit(packet)
        detection = self.decision.process(packet)
        detected = detection is not None
        self.metrics.evaluate_detection(packet.is_attack, detected)
        if detection:
            self.metrics.record_incident(
                IncidentRecord(
                    timestamp=packet.timestamp,
                    summary=detection.reason,
                    severity=detection.severity,
                    ip_address=packet.sender_ip,
                    mac_address=packet.sender_mac,
                    occurrences=detection.occurrences,
                )
            )
            self.incident_detected.emit(detection)
            message = (
                f"[{detection.severity.upper()}] {packet.sender_ip} -> {packet.target_ip} | {detection.reason}"
            )
            self.logger.log(message)
            self.log_generated.emit(message)
            if self.notifications:
                self.notifications.notify(detection)

    def ingest_simulated_packet(self, packet: ParsedARPPacket) -> None:
        """Allow injection of synthetic packets for evaluation scenarios."""

        self.process_parsed_packet(packet)

    def reset(self) -> None:
        self.cache = BindingCache()
        self.logger.clear()
        self.metrics = Metrics()
        self.rules = RuleMatchingModule(self.cache)
        if self._config:
            self.configure(self._config)
        else:
            self.thresholds = ThresholdEvaluator()
            self.decision = DecisionLogic(self.cache, self.rules, self.thresholds)
            self.resources = ResourceMonitor()
        self.log_generated.emit("Monitor state reset")

    def set_notification_manager(self, manager: Optional[NotificationManager]) -> None:
        self.notifications = manager
