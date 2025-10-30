"""Persistent event logging utilities."""
from __future__ import annotations

import json
import logging
import os
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from logging.handlers import RotatingFileHandler, SysLogHandler
from pathlib import Path
from typing import Deque, Iterable, List, Optional


LOG_DIR = Path(os.getenv("ARP_MONITOR_LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "arp_monitor.log"


_LEVEL_MAP = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
    "low": logging.INFO,
    "medium": logging.WARNING,
    "high": logging.ERROR,
}


@dataclass
class LogEntry:
    timestamp: datetime
    message: str
    level: str
    payload: Optional[dict[str, object]] = None


class EventLogger:
    """Write incidents to rotating file logs and optional syslog."""

    def __init__(
        self,
        *,
        log_path: Path | None = None,
        max_entries: int = 1024,
        syslog_address: str | tuple[str, int] | None = None,
    ) -> None:
        self._entries: Deque[LogEntry] = deque(maxlen=max_entries)
        self._log_path = log_path or LOG_FILE
        self._logger = logging.getLogger("arp_detector.events")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            self._install_handlers(syslog_address)

    def _install_handlers(self, syslog_address: str | tuple[str, int] | None) -> None:
        handler = RotatingFileHandler(self._log_path, maxBytes=5 * 1024 * 1024, backupCount=5)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)
        if syslog_address:
            syslog_handler = SysLogHandler(address=syslog_address)
            syslog_handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(syslog_handler)

    def log(self, message: str, *, payload: Optional[dict[str, object]] = None, level: str = "info") -> None:
        log_level = _LEVEL_MAP.get(level.lower(), logging.INFO)
        entry = LogEntry(
            timestamp=datetime.utcnow(),
            message=message,
            level=logging.getLevelName(log_level).lower(),
            payload=payload,
        )
        self._entries.append(entry)
        record = {
            "timestamp": entry.timestamp.isoformat(),
            "level": entry.level,
            "message": entry.message,
            "payload": payload or {},
        }
        try:
            self._logger.log(log_level, json.dumps(record))
        except Exception:  # pragma: no cover - logging failures are non-fatal
            logging.getLogger(__name__).exception("Failed to write event log entry")

    def entries(self) -> List[LogEntry]:
        return list(self._entries)

    def iter_entries(self) -> Iterable[LogEntry]:
        return iter(self._entries)

    def clear(self) -> None:
        self._entries.clear()

