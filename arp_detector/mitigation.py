"""Mitigation interface for ARP incidents.

In a production deployment this module would coordinate mitigation actions
such as sending corrective ARP announcements or isolating hosts.  In this
reference implementation we simply provide hooks and simulated behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .rules import DetectionEvent


@dataclass
class MitigationAction:
    description: str
    handler: Callable[[DetectionEvent], None]


class MitigationEngine:
    """Executes mitigation actions selected by the operator."""

    def __init__(self) -> None:
        self._registered = False

    def register_action(self, action: MitigationAction) -> None:
        self._action = action
        self._registered = True

    def mitigate(self, event: DetectionEvent) -> str:
        if not self._registered:
            return "No mitigation action registered"
        self._action.handler(event)
        return f"Mitigation executed: {self._action.description}"
