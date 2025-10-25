"""Persistent health status tracking for the ARP monitor."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

STATE_DIR = Path(os.getenv("ARP_MONITOR_STATE_DIR", "state"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_HEALTH_PATH = STATE_DIR / "monitor_health.json"


@dataclass
class HealthStatus:
    """In-memory representation of the monitor's health."""

    status: str = "stopped"
    interface: Optional[str] = None
    total_packets: int = 0
    incidents: int = 0
    suspicious_packets: int = 0
    last_packet_received: Optional[str] = None
    last_error: Optional[str] = None
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "status": self.status,
            "interface": self.interface,
            "total_packets": self.total_packets,
            "incidents": self.incidents,
            "suspicious_packets": self.suspicious_packets,
            "last_packet_received": self.last_packet_received,
            "last_error": self.last_error,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }
        payload.update(self.extra)
        return payload


class MonitorHealth:
    """Track and persist health state changes to disk."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or DEFAULT_HEALTH_PATH
        self._status = self._load()

    def _load(self) -> HealthStatus:
        if not self._path.exists():
            return HealthStatus()
        try:
            data = json.loads(self._path.read_text())
        except Exception:  # noqa: BLE001 - corruption should reset state
            return HealthStatus()
        status = HealthStatus()
        for key, value in data.items():
            if hasattr(status, key):
                setattr(status, key, value)
            else:
                status.extra[key] = value
        return status

    def _persist(self) -> None:
        self._status.updated_at = datetime.utcnow().isoformat()
        payload = self._status.to_dict()
        self._path.write_text(json.dumps(payload, indent=2))

    def configure(self, interface: Optional[str]) -> None:
        self._status.interface = interface
        self._persist()

    def started(self, interface: Optional[str]) -> None:
        self._status.status = "running"
        self._status.started_at = datetime.utcnow().isoformat()
        self._status.interface = interface
        self._status.last_error = None
        self._persist()

    def stopped(self) -> None:
        self._status.status = "stopped"
        self._persist()

    def failure(self, message: str) -> None:
        self._status.status = "error"
        self._status.last_error = message
        self._persist()

    def record_metrics(self, *, total_packets: int, incidents: int, suspicious_packets: int) -> None:
        self._status.total_packets = total_packets
        self._status.incidents = incidents
        self._status.suspicious_packets = suspicious_packets
        self._persist()

    def record_packet_timestamp(self, timestamp: datetime) -> None:
        self._status.last_packet_received = timestamp.isoformat()
        self._persist()

    def snapshot(self) -> Dict[str, Any]:
        return self._status.to_dict()


def load_health_status(path: Path | None = None) -> Dict[str, Any]:
    """Convenience helper for CLI health checks."""

    store = MonitorHealth(path)
    return store.snapshot()
