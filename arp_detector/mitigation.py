"""Mitigation interface for ARP incidents with approval workflows and auditing."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .rules import DetectionEvent


logger = logging.getLogger(__name__)

PreCheck = Callable[[DetectionEvent], Tuple[bool, str]]
PostVerification = Callable[[DetectionEvent, str], Tuple[bool, str]]
IntegrationHook = Callable[[DetectionEvent, str], None]


@dataclass
class MitigationAction:
    """Defines a mitigation workflow with approvals and validation."""

    action_id: str
    description: str
    handler: Callable[[DetectionEvent], str]
    required_roles: Sequence[str] = field(default_factory=lambda: ("operator",))
    pre_checks: Sequence[PreCheck] = field(default_factory=tuple)
    post_verifications: Sequence[PostVerification] = field(default_factory=tuple)
    integration_handler: Optional[IntegrationHook] = None
    integration_targets: Sequence[str] = field(default_factory=tuple)


@dataclass
class MitigationRecord:
    """Audit trail entry for mitigation actions."""

    timestamp: datetime
    action_id: str
    description: str
    actor: str
    roles_used: Sequence[str]
    status: str
    message: str


class MitigationEngine:
    """Executes mitigation actions with approvals, logging and verification."""

    def __init__(
        self,
        *,
        audit_logger: Optional[logging.Logger] = None,
        global_pre_checks: Sequence[PreCheck] | None = None,
        global_post_checks: Sequence[PostVerification] | None = None,
    ) -> None:
        self._actions: Dict[str, MitigationAction] = {}
        self._default: Optional[str] = None
        self._audit_logger = audit_logger or logging.getLogger("arp_detector.mitigation.audit")
        if not self._audit_logger.handlers:
            self._audit_logger.addHandler(logging.NullHandler())
        self._history: List[MitigationRecord] = []
        self._global_pre_checks: Sequence[PreCheck] = global_pre_checks or (
            self._ensure_binding_available,
        )
        self._global_post_checks: Sequence[PostVerification] = global_post_checks or (
            self._verify_binding_persisted,
        )

    # ------------------------------------------------------------------
    # Registration helpers
    def register_action(self, action: MitigationAction) -> None:
        if action.action_id in self._actions:
            raise ValueError(f"Mitigation action '{action.action_id}' already registered")
        self._actions[action.action_id] = action
        if self._default is None:
            self._default = action.action_id

    def register_shell_command(
        self,
        action_id: str,
        description: str,
        command: Sequence[str],
        *,
        required_roles: Sequence[str] | None = None,
        pre_checks: Sequence[PreCheck] | None = None,
        post_verifications: Sequence[PostVerification] | None = None,
        integration_handler: Optional[IntegrationHook] = None,
        integration_targets: Sequence[str] | None = None,
    ) -> None:
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
            logger.info(
                "Executed mitigation command",
                extra={
                    "action_id": action_id,
                    "command": rendered,
                    "return_code": result.returncode,
                },
            )
            if result.returncode != 0:
                stderr = result.stderr.strip() or "Unknown error"
                return f"Command {' '.join(rendered)} failed ({result.returncode}): {stderr}"
            stdout = result.stdout.strip() or "Command executed successfully"
            return stdout

        action = MitigationAction(
            action_id=action_id,
            description=description,
            handler=_handler,
            required_roles=required_roles or ("network-admin",),
            pre_checks=pre_checks or (),
            post_verifications=post_verifications or (),
            integration_handler=integration_handler,
            integration_targets=integration_targets or ("network-automation",),
        )
        self.register_action(action)

    # ------------------------------------------------------------------
    def available_actions(self) -> Iterable[MitigationAction]:
        return sorted(self._actions.values(), key=lambda action: action.description)

    def history(self) -> List[MitigationRecord]:
        return list(self._history)

    # ------------------------------------------------------------------
    def mitigate(
        self,
        event: DetectionEvent,
        action_identifier: Optional[str] = None,
        *,
        actor: str = "operator",
        role: str = "operator",
        approvals: Sequence[str] | None = None,
    ) -> str:
        if not self._actions:
            return "No mitigation action registered"

        try:
            action = self._resolve_action(action_identifier)
        except (KeyError, ValueError) as exc:
            return str(exc)
        provided_roles = {role}
        if approvals:
            provided_roles.update(approvals)
        required = set(action.required_roles)
        if not required.issubset(provided_roles):
            missing = ", ".join(sorted(required - provided_roles))
            message = f"Approval required from roles: {missing}"
            self._record_history(action, actor, provided_roles, "denied", message)
            return message

        pre_checks = list(self._global_pre_checks) + list(action.pre_checks)
        for check in pre_checks:
            ok, note = check(event)
            self._audit_logger.info(
                "Mitigation pre-check",
                extra={
                    "action_id": action.action_id,
                    "actor": actor,
                    "role": role,
                    "result": ok,
                    "message": note,
                },
            )
            if not ok:
                result = f"Pre-check failed: {note}"
                self._record_history(action, actor, provided_roles, "precheck_failed", result)
                return result

        try:
            outcome = action.handler(event)
        except Exception as exc:  # noqa: BLE001 - propagate failure details but keep running
            logger.exception("Mitigation action %s failed", action.action_id)
            outcome = f"Mitigation action '{action.description}' failed: {exc}"
            self._record_history(action, actor, provided_roles, "error", outcome)
            return outcome

        post_checks = list(action.post_verifications) + list(self._global_post_checks)
        post_messages: List[str] = []
        for check in post_checks:
            ok, note = check(event, outcome)
            post_messages.append(note)
            self._audit_logger.info(
                "Mitigation post-check",
                extra={
                    "action_id": action.action_id,
                    "actor": actor,
                    "role": role,
                    "result": ok,
                    "message": note,
                },
            )
            if not ok:
                outcome = f"{outcome}; post-verification warning: {note}"

        if action.integration_handler:
            try:
                action.integration_handler(event, outcome)
                self._audit_logger.info(
                    "Integration hook executed",
                    extra={
                        "action_id": action.action_id,
                        "actor": actor,
                        "targets": list(action.integration_targets) or ["custom"],
                    },
                )
            except Exception as exc:  # noqa: BLE001 - integration failures should be visible
                logger.exception("Integration hook for %s failed", action.action_id)
                outcome = f"{outcome}; integration error: {exc}"

        if post_messages:
            outcome = f"{outcome} (verification: {'; '.join(post_messages)})"

        self._record_history(action, actor, provided_roles, "completed", outcome)
        return outcome

    # ------------------------------------------------------------------
    def _resolve_action(self, action_identifier: Optional[str]) -> MitigationAction:
        if action_identifier is None:
            action_identifier = self._default
        if not action_identifier:
            raise ValueError("No mitigation action available")
        action = self._actions.get(action_identifier)
        if action:
            return action
        # allow lookup by description for backward compatibility
        for candidate in self._actions.values():
            if candidate.description == action_identifier:
                return candidate
        raise KeyError(f"Mitigation action '{action_identifier}' is unavailable")

    def _record_history(
        self,
        action: MitigationAction,
        actor: str,
        roles_used: Iterable[str],
        status: str,
        message: str,
    ) -> None:
        record = MitigationRecord(
            timestamp=datetime.utcnow(),
            action_id=action.action_id,
            description=action.description,
            actor=actor,
            roles_used=tuple(sorted(set(roles_used))),
            status=status,
            message=message,
        )
        self._history.append(record)
        self._audit_logger.info(
            "Mitigation action event",
            extra={
                "action_id": action.action_id,
                "status": status,
                "actor": actor,
                "message": message,
            },
        )

    # ------------------------------------------------------------------
    # Default validation helpers
    @staticmethod
    def _ensure_binding_available(event: DetectionEvent) -> Tuple[bool, str]:
        if event.binding is None:
            return False, "Binding information unavailable; ensure cache sharing is configured"
        return True, "Binding cache entry located"

    @staticmethod
    def _verify_binding_persisted(event: DetectionEvent, _outcome: str) -> Tuple[bool, str]:
        if event.binding is None:
            return False, "Binding cache entry missing after mitigation"
        return True, "Binding cache entry remains available for cross-sensor correlation"
