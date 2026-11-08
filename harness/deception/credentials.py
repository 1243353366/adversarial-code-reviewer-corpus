"""Credentials that look usable and cannot be.

Two rules decide the shape of this module.

*Generated, never copied.* Every value comes from HMAC over the seed plus the issuance,
so a review can re-derive it and confirm nothing was pasted in from a real store.

*Recognized by lookup, not by spelling.* The secret itself carries no "fake" marker,
because a marker in the secret teaches the attacker what to look for. Recognition happens
against the registry the listener owns.
"""
from __future__ import annotations

import base64
import string

from . import Issuance

KEY_ALPHABET = string.ascii_uppercase + string.digits
AWS_PREFIX = "AKIA"


class CredentialRegistry:
    """The listener's own record. The peer never sees this."""

    def __init__(self) -> None:
        self._by_value: dict[str, Issuance] = {}

    def _issue(self, issuance: Issuance, kind: str, value: str) -> str:
        self._by_value[value] = issuance
        return value

    def aws_like(self, issuance: Issuance) -> str:
        raw = issuance.stream("aws")
        body = "".join(KEY_ALPHABET[b % len(KEY_ALPHABET)] for b in raw[:16])
        return self._issue(issuance, "aws_like", AWS_PREFIX + body)

    def secret_key(self, issuance: Issuance) -> str:
        raw = issuance.stream("secret")
        return self._issue(issuance, "secret", base64.b64encode(raw).decode().rstrip("="))

    def db_password(self, issuance: Issuance) -> str:
        raw = issuance.stream("db")
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return self._issue(issuance, "db_password", "".join(alphabet[b % len(alphabet)] for b in raw[:24]))

    def ssh_stub(self, issuance: Issuance) -> str:
        """Structurally plausible, deliberately not a working key: no curve parameters."""
        body = base64.b64encode(issuance.stream("ssh")).decode()
        text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{issuance.fingerprint('ssh_header', 8)}SYNTHETIC--NOT-A-KEY\n{body}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        return self._issue(issuance, "ssh_stub", text)

    def attribute(self, value: str) -> Issuance | None:
        """Which issuance this exact value came from, if any."""
        return self._by_value.get(value)

    def known(self, value: str) -> bool:
        return value in self._by_value

    def __len__(self) -> int:
        return len(self._by_value)
