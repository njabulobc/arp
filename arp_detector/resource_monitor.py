"""System resource sampling utilities."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

from .metrics import ResourceSnapshot

try:  # pragma: no cover - fallback only
    from time import monotonic as _monotonic
except ImportError:  # pragma: no cover
    from time import time as _monotonic


logger = logging.getLogger(__name__)

STATE_DIR = Path(os.getenv("ARP_MONITOR_STATE_DIR", "state"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
SNAPSHOT_PATH = STATE_DIR / "resource_snapshot.json"


@dataclass
class _CounterState:
    total_bytes: int
    timestamp: float


class ResourceMonitor:
    """Track CPU utilisation and network bandwidth usage."""

    def __init__(self, interface: Optional[str] = None, enabled: bool = True) -> None:
        self.interface = interface
        self._previous: Optional[_CounterState] = None
        self._enabled = enabled
        self._last_error: Optional[str] = None

    def set_interface(self, interface: Optional[str]) -> None:
        self.interface = interface
        self._previous = None

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        if not enabled:
            self._previous = None

    def sample(self) -> Optional[ResourceSnapshot]:
        """Capture a resource usage sample."""

        if not self._enabled:
            return None

        try:
            cpu_percent = psutil.cpu_percent(interval=None)
        except Exception as exc:  # noqa: BLE001
            self._report_failure("cpu_percent", exc)
            return None

        counters = self._capture_counters()
        if counters is None:
            return None

        now = datetime.utcnow()
        bytes_per_sec = 0.0

        current_time = _monotonic()
        if self._previous is None:
            self._previous = _CounterState(total_bytes=counters, timestamp=current_time)
        else:
            delta_bytes = counters - self._previous.total_bytes
            delta_time = max(current_time - self._previous.timestamp, 1e-6)
            bytes_per_sec = delta_bytes / delta_time
            self._previous = _CounterState(total_bytes=counters, timestamp=current_time)

        snapshot = ResourceSnapshot(
            timestamp=now,
            cpu_percent=cpu_percent,
            bandwidth_bytes_per_sec=bytes_per_sec,
        )
        self._persist_snapshot(snapshot)
        self._last_error = None
        return snapshot

    def _capture_counters(self) -> Optional[int]:
        """Return the cumulative bytes sent+received for the configured interface."""

        try:
            if self.interface:
                pernic = psutil.net_io_counters(pernic=True)
                stats = pernic.get(self.interface)
                if stats is None:
                    raise KeyError(f"Interface '{self.interface}' has no counters")
            else:
                stats = psutil.net_io_counters()
        except Exception as exc:  # noqa: BLE001
            self._report_failure("net_io_counters", exc)
            return None

        return int(stats.bytes_sent + stats.bytes_recv)

    def _persist_snapshot(self, snapshot: ResourceSnapshot) -> None:
        try:
            payload = {
                "timestamp": snapshot.timestamp.isoformat(),
                "cpu_percent": snapshot.cpu_percent,
                "bandwidth_bytes_per_sec": snapshot.bandwidth_bytes_per_sec,
            }
            SNAPSHOT_PATH.write_text(json.dumps(payload, indent=2))
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to persist resource snapshot: %s", exc)

    def _report_failure(self, operation: str, exc: Exception) -> None:
        message = f"Resource sampling failed during {operation}: {exc}"
        if self._last_error == message:
            return
        self._last_error = message
        logger.warning(message)

