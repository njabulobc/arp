"""High level ARP monitoring controller."""
from __future__ import annotations

import importlib.util
import logging
from dataclasses import dataclass
from typing import Optional

if importlib.util.find_spec("PyQt5") is not None:  # pragma: no cover - optional dependency
    from PyQt5.QtCore import QObject, pyqtSignal
else:  # pragma: no cover - lightweight signal fallback
    class QObject:  # type: ignore[override]
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ANN001, ANN002
            """Simplified QObject replacement for headless environments."""

    class _Signal:
        def __init__(self) -> None:
            self._callbacks: list = []

        def connect(self, callback):  # noqa: ANN001
            self._callbacks.append(callback)

        def emit(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            for callback in list(self._callbacks):
                callback(*args, **kwargs)

    class _SignalDescriptor:
        def __set_name__(self, owner, name):  # noqa: ANN001, ANN101
            self._name = name

        def __get__(self, instance, owner=None):  # noqa: ANN001, ANN002
            if instance is None:
                return self
            signal = instance.__dict__.get(self._name)
            if signal is None:
                signal = _Signal()
                instance.__dict__[self._name] = signal
            return signal

    def pyqtSignal(*_args, **_kwargs):  # noqa: ANN001, ANN002
        return _SignalDescriptor()
from scapy.all import AsyncSniffer, get_if_list
from scapy.layers.l2 import ARP

from .binding_cache import BindingCache
from .event_logger import EventLogger
from .health import MonitorHealth
from .metrics import IncidentRecord, Metrics
from .notifications import (
    NotificationManager,
    NotificationPolicy,
    build_structured_event,
)
from .parser import PacketParser, ParsedARPPacket
from .resource_monitor import ResourceMonitor
from .rules import DecisionLogic, DetectionEvent, RuleMatchingModule, ThresholdEvaluator


logger = logging.getLogger(__name__)


@dataclass
class MonitorConfig:
    interface: Optional[str]
    window_seconds: int
    detection_threshold: int
    high_severity_threshold: int
    alert_warning_threshold: int = 1
    alert_critical_threshold: int = 3
    collect_resources: bool = True


class MonitorError(RuntimeError):
    """Base class for monitor related failures."""


class MonitorConfigurationError(MonitorError):
    """Raised when the monitor cannot accept a configuration."""


class MonitorRuntimeError(MonitorError):
    """Raised when monitoring cannot start or continue."""


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
        self.health = MonitorHealth()

    def available_interfaces(self) -> list[str]:
        return get_if_list()

    def configure(self, config: MonitorConfig) -> None:
        interfaces: set[str] = set()
        try:
            interfaces = set(self.available_interfaces())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to enumerate interfaces: %s", exc)

        if config.interface:
            if interfaces and config.interface not in interfaces:
                message = (
                    f"Interface '{config.interface}' is not available; known interfaces: {sorted(interfaces)}"
                )
                self.log_generated.emit(message)
                raise MonitorConfigurationError(message)

        self._config = config
        self.cache = BindingCache()
        self.metrics = Metrics()
        self.rules = RuleMatchingModule(self.cache)
        self.thresholds = ThresholdEvaluator(
            window_seconds=config.window_seconds,
            detection_trigger=config.detection_threshold,
            high_trigger=config.high_severity_threshold,
        )
        self.decision = DecisionLogic(self.cache, self.rules, self.thresholds)
        self.logger.clear()

        self.resources = ResourceMonitor(interface=config.interface, enabled=config.collect_resources)
        if self.notifications:
            policy = NotificationPolicy(
                warning_threshold=config.alert_warning_threshold,
                critical_threshold=config.alert_critical_threshold,
            )
            self.notifications.configure(policy)
        self.health.configure(config.interface)
        self.health.record_metrics(total_packets=0, incidents=0, suspicious_packets=0)
        self.log_generated.emit(
            "Configured monitor: interface="
            f"{config.interface or 'all'}, window={config.window_seconds}s, "
            f"detect>={config.detection_threshold}, high>={config.high_severity_threshold}, "
            f"alert warn>={config.alert_warning_threshold}, critical>={config.alert_critical_threshold}, "
            f"resources={'enabled' if config.collect_resources else 'disabled'}"
        )

    def start(self) -> None:
        if self.sniffer and self.sniffer.running:
            return
        if not self._config:
            raise MonitorConfigurationError("Monitor must be configured before starting")
        iface = self._config.interface
        try:
            self.sniffer = AsyncSniffer(
                iface=iface,
                filter="arp",
                prn=self._handle_packet,
                store=False,
            )
            self.sniffer.start()
        except Exception as exc:  # noqa: BLE001
            self.sniffer = None
            message = f"Failed to start ARP capture on interface '{iface or 'all'}': {exc}"
            self.logger.log(message, level="error")
            self.log_generated.emit(message)
            self.health.failure(message)
            raise MonitorRuntimeError(message) from exc
        self.health.started(iface)
        self.log_generated.emit("ARP monitor started")

    def stop(self) -> None:
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.sniffer = None
            self.log_generated.emit("ARP monitor stopped")
        self.health.stopped()

    def _handle_packet(self, packet) -> None:
        if not packet.haslayer(ARP):
            return
        parsed = PacketParser.parse(packet)
        self.process_parsed_packet(parsed)

    def process_parsed_packet(self, packet: ParsedARPPacket) -> None:
        snapshot = self.resources.sample()
        self.metrics.record_packet(packet, snapshot)
        self.health.record_metrics(
            total_packets=self.metrics.total_packets,
            incidents=len(self.metrics.incidents),
            suspicious_packets=self.metrics.suspicious_packets,
        )
        self.health.record_packet_timestamp(packet.timestamp)
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
            self.health.record_metrics(
                total_packets=self.metrics.total_packets,
                incidents=len(self.metrics.incidents),
                suspicious_packets=self.metrics.suspicious_packets,
            )
            self.incident_detected.emit(detection)
            structured = build_structured_event(detection, detection.severity)
            message = structured["summary"]
            self.logger.log(message, payload=structured, level=detection.severity)
            self.log_generated.emit(message)
            if self.notifications:
                payload = self.notifications.notify(detection)
                if payload and self.notifications.has_channels():
                    self.logger.log(
                        "Notification dispatched",
                        payload=payload,
                        level="info",
                    )

    def ingest_simulated_packet(self, packet: ParsedARPPacket) -> None:
        """Allow injection of synthetic packets for evaluation scenarios."""

        self.process_parsed_packet(packet)

    def reset(self) -> None:
        self.cache = BindingCache()
        self.metrics = Metrics()
        self.logger.clear()
        self.rules = RuleMatchingModule(self.cache)
        if self._config:
            self.configure(self._config)
        else:
            self.thresholds = ThresholdEvaluator()
            self.decision = DecisionLogic(self.cache, self.rules, self.thresholds)
            self.resources = ResourceMonitor()
            self.health.record_metrics(total_packets=0, incidents=0, suspicious_packets=0)
        self.health.stopped()
        self.log_generated.emit("Monitor state reset")

    def set_notification_manager(self, manager: Optional[NotificationManager]) -> None:
        self.notifications = manager
