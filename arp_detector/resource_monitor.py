"""System resource sampling utilities."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import psutil

from .metrics import ResourceSnapshot

try:  # pragma: no cover - fallback only
    from time import monotonic as _monotonic
except ImportError:  # pragma: no cover
    from time import time as _monotonic


@dataclass
class _CounterState:
    total_bytes: int
    timestamp: float


class ResourceMonitor:
    """Track CPU utilisation and network bandwidth usage."""

    def __init__(self, interface: Optional[str] = None) -> None:
        self.interface = interface
        self._previous: Optional[_CounterState] = None

    def set_interface(self, interface: Optional[str]) -> None:
        self.interface = interface
        self._previous = None

    def sample(self) -> ResourceSnapshot:
        """Capture a resource usage sample."""

        cpu_percent = psutil.cpu_percent(interval=None)
        counters = self._capture_counters()
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

        return ResourceSnapshot(
            timestamp=now,
            cpu_percent=cpu_percent,
            bandwidth_bytes_per_sec=bytes_per_sec,
        )

    def _capture_counters(self) -> int:
        """Return the cumulative bytes sent+received for the configured interface."""

        if self.interface:
            pernic = psutil.net_io_counters(pernic=True)
            stats = pernic.get(self.interface)
            if stats is None:
                # Fall back to aggregate if the interface is not present.
                stats = psutil.net_io_counters()
        else:
            stats = psutil.net_io_counters()
        return int(stats.bytes_sent + stats.bytes_recv)
