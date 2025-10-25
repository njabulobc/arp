"""Notification management for ARP detector alerts."""
from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Callable, Iterable, List, Optional

from .rules import DetectionEvent


logger = logging.getLogger(__name__)


ALERT_LEVELS = ["info", "warning", "critical"]


def _level_priority(level: str) -> int:
    try:
        return ALERT_LEVELS.index(level)
    except ValueError:
        return 0


@dataclass
class NotificationPolicy:
    """Defines escalation thresholds for alerting."""

    warning_threshold: int = 1
    critical_threshold: int = 3


@dataclass
class NotificationChannel:
    """Generic alerting channel."""

    name: str
    minimum_level: str
    dispatcher: Callable[[DetectionEvent, str, str], None]

    def notify(self, event: DetectionEvent, level: str, message: str) -> None:
        if _level_priority(level) >= _level_priority(self.minimum_level):
            self.dispatcher(event, level, message)


class NotificationManager:
    """Coordinate alert dispatch to registered channels."""

    def __init__(self, policy: Optional[NotificationPolicy] = None) -> None:
        self.policy = policy or NotificationPolicy()
        self._channels: List[NotificationChannel] = []

    def configure(self, policy: NotificationPolicy) -> None:
        self.policy = policy

    def register_channel(self, channel: NotificationChannel) -> None:
        self._channels.append(channel)

    def clear_channels(self) -> None:
        self._channels.clear()

    def notify(self, event: DetectionEvent) -> None:
        if not self._channels:
            return

        level = self._determine_level(event)
        message = (
            f"[{level.upper()}] ARP alert for {event.packet.sender_ip} -> {event.packet.target_ip}: {event.reason}"
        )
        for channel in self._channels:
            try:
                channel.notify(event, level, message)
            except Exception:  # pragma: no cover - defensive logging path
                logger.exception("Notification channel '%s' failed", channel.name)

    def _determine_level(self, event: DetectionEvent) -> str:
        if event.occurrences >= self.policy.critical_threshold or event.severity == "high":
            return "critical"
        if event.occurrences >= self.policy.warning_threshold or event.severity == "medium":
            return "warning"
        return "info"


def create_email_channel(
    name: str,
    minimum_level: str,
    sender: str,
    recipients: Iterable[str],
    smtp_host: str,
    smtp_port: int = 25,
) -> NotificationChannel:
    """Create an SMTP-backed notification channel."""

    def _send_email(event: DetectionEvent, level: str, message: str) -> None:
        email = EmailMessage()
        email["From"] = sender
        email["To"] = ", ".join(recipients)
        email["Subject"] = f"ARP Detector {level.title()} Alert"
        email.set_content(
            "\n".join(
                [
                    message,
                    "",
                    f"Severity: {event.severity}",
                    f"Occurrences: {event.occurrences}",
                    f"Source IP: {event.packet.sender_ip}",
                    f"Source MAC: {event.packet.sender_mac}",
                    f"Target IP: {event.packet.target_ip}",
                    f"Target MAC: {event.packet.target_mac}",
                ]
            )
        )
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as client:
            client.send_message(email)

    return NotificationChannel(name=name, minimum_level=minimum_level, dispatcher=_send_email)


def create_callback_channel(
    name: str,
    minimum_level: str,
    callback: Callable[[DetectionEvent, str, str], None],
) -> NotificationChannel:
    """Create a callback-driven channel (e.g., GUI pop-up or logging)."""

    return NotificationChannel(name=name, minimum_level=minimum_level, dispatcher=callback)
