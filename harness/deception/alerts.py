"""Canaries and the alert path they feed.

A canary that nobody is watching is decoration. This module closes the loop in the only
way available offline: it turns any text the listener later sees into alerts, and it
distinguishes *which* artifact leaked from *which* campaign it belonged to.

The registry is append-only by convention and keyed by the marks themselves, so a match
survives the peer copying, quoting, re-encoding or reassembling the text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import Issuance
from . import watermark
from .credentials import CredentialRegistry

HONEY_HOST = "internal-metrics.invalid"


@dataclass(frozen=True)
class Alert:
    kind: str
    issuance_id: str
    campaign: str
    detail: str
    first_seen: str


@dataclass
class CanaryLedger:
    """Issuances outstanding, and what has fired so far."""

    registry: CredentialRegistry
    issuances: dict[str, Issuance] = field(default_factory=dict)
    alerts: list[Alert] = field(default_factory=list)
    _seen: set[tuple[str, str]] = field(default_factory=set)

    def issue(self, issuance: Issuance) -> Issuance:
        self.issuances[issuance.issuance_id] = issuance
        return issuance

    def canary_url(self, issuance: Issuance) -> str:
        """A URL nobody legitimate would fetch, carrying the issuance mark."""
        return f"https://{HONEY_HOST}/t/{issuance.fingerprint('canary', 20)}"

    def _fire(self, kind: str, issuance_id: str, detail: str) -> None:
        key = (kind, issuance_id)
        if key in self._seen:
            return
        self._seen.add(key)
        issuance = self.issuances.get(issuance_id)
        self.alerts.append(
            Alert(
                kind=kind,
                issuance_id=issuance_id,
                campaign=issuance.campaign if issuance else "unknown",
                detail=detail,
                first_seen=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        )

    def scan(self, text: str, kind: str = "watermark_seen") -> list[Alert]:
        """Attribute arbitrary text: marks first, then exact credential values."""
        before = len(self.alerts)
        for key in watermark.attribute(text):
            for issuance_id, issuance in self.issuances.items():
                if issuance.fingerprint("mark", 8) == key:
                    self._fire(kind, issuance_id, f"mark {key} recovered from text")
        for value, issuance in self.registry._by_value.items():  # noqa: SLF001 - same package
            if value and value in text:
                self._fire("credential_used", issuance.issuance_id, "exact credential value appeared")
        return self.alerts[before:]

    def summary(self) -> dict:
        fired = {a.issuance_id for a in self.alerts}
        return {
            "issued": len(self.issuances),
            "alerts": len(self.alerts),
            "silent": sorted(set(self.issuances) - fired),
        }
