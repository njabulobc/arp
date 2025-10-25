"""Mitigation interface for ARP incidents.

In a production deployment this module would coordinate mitigation actions
such as sending corrective ARP announcements or isolating hosts.  In this
reference implementation we simply provide hooks and simulated behaviour.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Optional, Sequence

from .rules import DetectionEvent


@dataclass
class MitigationAction:
    description: str
    handler: Callable[[DetectionEvent], str]


class MitigationEngine:
    """Executes mitigation actions selected by the operator."""

    def __init__(self) -> None:
        self._actions: Dict[str, MitigationAction] = {}
        self._default: Optional[str] = None

    def register_action(self, action: MitigationAction) -> None:
        self._actions[action.description] = action
        if self._default is None:
            self._default = action.description

    def register_shell_command(self, description: str, command: Sequence[str]) -> None:
        """Register a mitigation that executes a shell command."""

        def _handler(event: DetectionEvent) -> str:
            substitutions = {
                "src_ip": event.packet.sender_ip,
                "src_mac": event.packet.sender_mac,
                "target_ip": event.packet.target_ip,
                "target_mac": event.packet.target_mac,
            }
            rendered = [part.format(**substitutions) for part in command]
            result = subprocess.run(rendered, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                stderr = result.stderr.strip() or "Unknown error"
                return f"Command {' '.join(rendered)} failed ({result.returncode}): {stderr}"
            stdout = result.stdout.strip() or "Command executed successfully"
            return stdout

        self.register_action(MitigationAction(description, _handler))

    def available_actions(self) -> Iterable[MitigationAction]:
        return list(self._actions.values())

    def mitigate(self, event: DetectionEvent, action_description: Optional[str] = None) -> str:
        if not self._actions:
            return "No mitigation action registered"

        description = action_description or self._default
        action = self._actions.get(description or "")
        if not action:
            return "Requested mitigation action is unavailable"
        return action.handler(event)
