"""Signature heuristics for identifying known ARP spoofing tools."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Sequence

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .parser import ParsedARPPacket


@dataclass(frozen=True)
class SpoofingSignature:
    """Defines a detection signature for ARP spoofing tools."""

    name: str
    description: str
    matcher: Callable[["ParsedARPPacket"], bool]


def _default_signatures() -> Sequence[SpoofingSignature]:
    from .parser import ParsedARPPacket  # local import to avoid circular dependencies

    def arpspoof_signature(packet: "ParsedARPPacket") -> bool:
        return packet.operation == "reply" and packet.target_mac.lower() == "ff:ff:ff:ff:ff:ff"

    def ettercap_signature(packet: "ParsedARPPacket") -> bool:
        return (
            packet.operation == "reply"
            and packet.target_ip == packet.sender_ip
            and packet.raw.get("hwlen") == 6
        )

    def bettercap_signature(packet: "ParsedARPPacket") -> bool:
        return (
            packet.operation == "reply"
            and packet.raw.get("op") == 2
            and packet.raw.get("ptype") == 0x800
            and packet.raw.get("hwtype") == 1
            and packet.sender_mac.lower().startswith("02:")
        )

    return (
        SpoofingSignature(
            name="arpspoof_broadcast",
            description="arpspoof-style broadcast reply",
            matcher=arpspoof_signature,
        ),
        SpoofingSignature(
            name="ettercap_gratuitous",
            description="ettercap gratuitous reply pattern",
            matcher=ettercap_signature,
        ),
        SpoofingSignature(
            name="bettercap_locally_administered",
            description="bettercap locally administered MAC pattern",
            matcher=bettercap_signature,
        ),
    )


class SignatureMatcher:
    """Evaluate packets against known spoofing signatures."""

    def __init__(self, signatures: Iterable[SpoofingSignature] | None = None) -> None:
        self._signatures = list(signatures or _default_signatures())

    def match(self, packet: "ParsedARPPacket") -> List[str]:
        matches: List[str] = []
        for signature in self._signatures:
            try:
                if signature.matcher(packet):
                    matches.append(signature.description)
            except Exception:  # noqa: BLE001 - malformed packets should not break matching
                continue
        return matches
