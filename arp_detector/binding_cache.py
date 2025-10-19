"""Binding cache for tracking IP to MAC address associations.

The cache keeps the latest observed MAC address and timestamp for each IP.
It also keeps historical MACs to help with conflict detection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional


@dataclass
class BindingEntry:
    """Represents a binding between an IP address and a MAC address."""

    ip_address: str
    mac_address: str
    last_seen: datetime = field(default_factory=datetime.utcnow)
    history: List[str] = field(default_factory=list)

    def update(self, mac_address: str) -> None:
        """Update the entry with a new MAC address."""
        self.last_seen = datetime.utcnow()
        if mac_address != self.mac_address:
            if self.mac_address not in self.history:
                self.history.append(self.mac_address)
            self.mac_address = mac_address


class BindingCache:
    """Caches IP/MAC bindings and provides conflict detection."""

    def __init__(self, retention_seconds: int = 300) -> None:
        self._entries: Dict[str, BindingEntry] = {}
        self.retention = timedelta(seconds=retention_seconds)

    def get(self, ip_address: str) -> Optional[BindingEntry]:
        return self._entries.get(ip_address)

    def update(self, ip_address: str, mac_address: str) -> BindingEntry:
        entry = self._entries.get(ip_address)
        if entry is None:
            entry = BindingEntry(ip_address=ip_address, mac_address=mac_address)
            self._entries[ip_address] = entry
        else:
            entry.update(mac_address)
        return entry

    def detect_conflict(self, ip_address: str, mac_address: str) -> bool:
        """Returns True when an IP is associated with multiple MAC addresses."""
        entry = self._entries.get(ip_address)
        if entry is None:
            return False
        if entry.mac_address == mac_address:
            return False
        return mac_address in entry.history or entry.mac_address != mac_address

    def purge_stale(self) -> None:
        """Remove bindings that have not been seen recently."""
        now = datetime.utcnow()
        to_delete = [ip for ip, entry in self._entries.items() if now - entry.last_seen > self.retention]
        for ip in to_delete:
            del self._entries[ip]

    def entries(self) -> Iterable[BindingEntry]:
        return self._entries.values()
