"""Deception layer: everything a peer can steal is fabricated, marked, and attributable.

The design goal is narrower than "trap the attacker". Three properties, in order:

1. Nothing here is real. Credentials are generated, the filesystem is in memory, command
   output is synthesized. There is no path from this package to a host account or file.
2. Every artifact is individually marked, so a leak says *which* issuance leaked, not
   merely which campaign.
3. Stripping the obvious marker leaves a second one, and using the artifact is what
   triggers the alert, not finding it.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac

SEED = b"deception-layer-v1"


@dataclass(frozen=True)
class Issuance:
    """One fabricated package handed to one place at one time."""

    campaign: str
    issuance_id: str
    issued_at: str

    @staticmethod
    def create(campaign: str, issuance_id: str) -> "Issuance":
        return Issuance(campaign, issuance_id, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def stream(self, purpose: str) -> bytes:
        """Deterministic bytes for this issuance and purpose. Same inputs, same output."""
        return hmac.new(SEED, f"{self.campaign}|{self.issuance_id}|{purpose}".encode(), hashlib.sha256).digest()

    def fingerprint(self, purpose: str = "default", length: int = 12) -> str:
        return self.stream(purpose).hex()[:length]
