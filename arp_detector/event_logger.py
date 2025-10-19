"""Simple in-memory event logger for incidents."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List


@dataclass
class LogEntry:
    timestamp: datetime
    message: str


class EventLogger:
    def __init__(self) -> None:
        self._entries: List[LogEntry] = []

    def log(self, message: str) -> None:
        self._entries.append(LogEntry(timestamp=datetime.utcnow(), message=message))

    def entries(self) -> List[LogEntry]:
        return list(self._entries)

    def clear(self) -> None:
        self._entries.clear()
