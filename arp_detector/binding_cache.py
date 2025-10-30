"""Binding cache for tracking IP to MAC address associations with persistence."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional


STATE_DIR = Path(os.getenv("ARP_MONITOR_STATE_DIR", "state"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
BINDING_CACHE_PATH = STATE_DIR / "binding_cache.json"
DHCP_LEASES_PATH = STATE_DIR / "dhcp_leases.json"
ASSET_SENSITIVITY_PATH = STATE_DIR / "asset_sensitivity.json"


def _parse_timestamp(value: str | None) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _serialise_timestamp(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


@dataclass
class BindingHistoryRecord:
    """Historical observation of an IP-to-MAC binding."""

    mac_address: str
    vlan: Optional[int]
    observed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, object]:
        return {
            "mac_address": self.mac_address,
            "vlan": self.vlan,
            "observed_at": _serialise_timestamp(self.observed_at),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "BindingHistoryRecord":
        return cls(
            mac_address=str(payload.get("mac_address", "")),
            vlan=payload.get("vlan"),
            observed_at=_parse_timestamp(payload.get("observed_at") or None) or datetime.utcnow(),
        )


@dataclass
class BindingEntry:
    """Represents a binding between an IP address and a MAC address."""

    ip_address: str
    mac_address: str
    vlan: Optional[int] = None
    last_seen: datetime = field(default_factory=datetime.utcnow)
    history: List[BindingHistoryRecord] = field(default_factory=list)
    sensitivity: float = 1.0

    def update(self, mac_address: str, vlan: Optional[int]) -> None:
        """Update the entry with a new MAC address and VLAN context."""

        now = datetime.utcnow()
        if mac_address != self.mac_address or vlan != self.vlan:
            self.history.append(
                BindingHistoryRecord(mac_address=self.mac_address, vlan=self.vlan, observed_at=self.last_seen)
            )
            self.mac_address = mac_address
            self.vlan = vlan
        self.last_seen = now

    def to_dict(self) -> dict[str, object]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "vlan": self.vlan,
            "last_seen": self.last_seen.isoformat(),
            "history": [record.to_dict() for record in self.history],
            "sensitivity": self.sensitivity,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "BindingEntry":
        entry = cls(
            ip_address=str(payload.get("ip_address", "")),
            mac_address=str(payload.get("mac_address", "")),
            vlan=payload.get("vlan"),
            last_seen=_parse_timestamp(payload.get("last_seen") or None) or datetime.utcnow(),
            sensitivity=float(payload.get("sensitivity", 1.0) or 1.0),
        )
        history_payload = payload.get("history", []) or []
        entry.history = [BindingHistoryRecord.from_dict(item) for item in history_payload]
        return entry


class BindingCache:
    """Caches IP/MAC bindings, DHCP leases and sensitivity metadata."""

    def __init__(self, retention_seconds: int = 300, *, path: Path | None = None) -> None:
        self.retention = timedelta(seconds=retention_seconds)
        self._path = path or BINDING_CACHE_PATH
        self._entries: Dict[str, BindingEntry] = {}
        self._dhcp_leases: Dict[str, dict[str, object]] = {}
        self._asset_sensitivity: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_loaded: Optional[float] = None
        self._load()

    # ------------------------------------------------------------------
    # Persistence helpers
    def _load(self) -> None:
        with self._lock:
            if self._path.exists():
                try:
                    data = json.loads(self._path.read_text())
                except Exception:  # noqa: BLE001 - corrupted cache should be reset
                    data = {}
                entries_payload = data.get("entries", [])
                self._entries = {}
                for item in entries_payload:
                    entry = BindingEntry.from_dict(item)
                    if entry.ip_address:
                        self._entries[entry.ip_address] = entry
                self._asset_sensitivity = {
                    ip: float(value)
                    for ip, value in (data.get("asset_sensitivity", {}) or {}).items()
                }
                for ip, entry in self._entries.items():
                    self._asset_sensitivity.setdefault(ip, entry.sensitivity)
                for ip, entry in self._entries.items():
                    if ip in self._asset_sensitivity:
                        entry.sensitivity = self._asset_sensitivity[ip]
                self._last_loaded = self._path.stat().st_mtime
            else:
                self._entries = {}
                self._asset_sensitivity = {}

            self._dhcp_leases = self._load_json_file(DHCP_LEASES_PATH)
            sensitivity_override = self._load_json_file(ASSET_SENSITIVITY_PATH)
            if sensitivity_override:
                self._asset_sensitivity.update({ip: float(value) for ip, value in sensitivity_override.items()})
                for ip, weight in self._asset_sensitivity.items():
                    entry = self._entries.get(ip)
                    if entry:
                        entry.sensitivity = weight

    def _maybe_refresh_from_disk(self) -> None:
        if not self._path.exists():
            return
        mtime = self._path.stat().st_mtime
        if self._last_loaded is None or mtime > self._last_loaded:
            self._load()

    def _persist(self) -> None:
        with self._lock:
            payload = {
                "entries": [entry.to_dict() for entry in self._entries.values()],
                "asset_sensitivity": self._asset_sensitivity,
            }
            temp_path = self._path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(payload, indent=2))
            temp_path.replace(self._path)
            self._last_loaded = self._path.stat().st_mtime

    @staticmethod
    def _load_json_file(path: Path) -> Dict[str, object]:
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text())
        except Exception:  # noqa: BLE001 - fall back to empty structure on parse errors
            return {}
        if isinstance(data, dict):
            return data
        return {}

    # ------------------------------------------------------------------
    # Public API
    def clear(self) -> None:
        """Remove all cached bindings and persist the change."""

        self._entries.clear()
        self._persist()

    def get(self, ip_address: str) -> Optional[BindingEntry]:
        self._maybe_refresh_from_disk()
        return self._entries.get(ip_address)

    def update(self, ip_address: str, mac_address: str, vlan: Optional[int] = None) -> BindingEntry:
        self._maybe_refresh_from_disk()
        entry = self._entries.get(ip_address)
        if entry is None:
            entry = BindingEntry(ip_address=ip_address, mac_address=mac_address, vlan=vlan)
            entry.sensitivity = self._asset_sensitivity.get(ip_address, entry.sensitivity)
            self._entries[ip_address] = entry
        else:
            entry.update(mac_address, vlan)
        self._persist()
        return entry

    def detect_conflict(self, ip_address: str, mac_address: str, vlan: Optional[int] = None) -> bool:
        """Returns True when an IP is associated with multiple MAC addresses or VLANs."""

        entry = self._entries.get(ip_address)
        if entry is None:
            return False
        if entry.mac_address == mac_address and entry.vlan == vlan:
            return False
        if entry.mac_address != mac_address:
            return True
        if vlan is not None and entry.vlan is not None and entry.vlan != vlan:
            return True
        return any(record.mac_address == mac_address and record.vlan == vlan for record in entry.history)

    def detect_vlan_conflict(self, ip_address: str, vlan: Optional[int]) -> bool:
        """Check whether the observed VLAN deviates from the cached VLAN."""

        if vlan is None:
            return False
        entry = self._entries.get(ip_address)
        if entry is None:
            return False
        if entry.vlan is None:
            return False
        return entry.vlan != vlan

    def dhcp_mac_for(self, ip_address: str) -> Optional[str]:
        lease = self._dhcp_leases.get(ip_address)
        if not isinstance(lease, dict):
            return None
        mac = lease.get("mac") or lease.get("mac_address")
        return str(mac) if mac else None

    def dhcp_vlan_for(self, ip_address: str) -> Optional[int]:
        lease = self._dhcp_leases.get(ip_address)
        if not isinstance(lease, dict):
            return None
        vlan = lease.get("vlan")
        if vlan is None:
            return None
        try:
            return int(vlan)
        except (TypeError, ValueError):
            return None

    def asset_weight(self, ip_address: str) -> float:
        return self._asset_sensitivity.get(ip_address, 1.0)

    def purge_stale(self) -> None:
        """Remove bindings that have not been seen recently."""

        self._maybe_refresh_from_disk()
        now = datetime.utcnow()
        to_delete = [ip for ip, entry in self._entries.items() if now - entry.last_seen > self.retention]
        for ip in to_delete:
            del self._entries[ip]
        if to_delete:
            self._persist()

    def entries(self) -> Iterable[BindingEntry]:
        self._maybe_refresh_from_disk()
        return list(self._entries.values())
