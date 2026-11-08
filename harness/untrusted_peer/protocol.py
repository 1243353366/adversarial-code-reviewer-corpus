"""Wire format shared by both implementations.

Frame = 4-byte big-endian unsigned length, then that many bytes of UTF-8 JSON.
The length field is written by the peer. That is the whole problem.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field

MAX_FRAME = 64 * 1024
MAX_WALL_SECONDS = 5.0
MAX_FRAMES_PER_CONNECTION = 100
ALLOWED_TYPES = {"heartbeat", "observation"}
ALLOWED_KEYS = {"type", "seq", "note"}
CONTROL_CHARS = "".join(chr(c) for c in range(0x20) if c not in (0x0A, 0x09)) + "\x7f"


class ProtocolError(Exception):
    """Raised when a peer's bytes are not acceptable. Never fatal to the listener."""


@dataclass
class Rejections:
    """Every refusal is counted, because an unlogged rejection is an invisible one."""

    counts: dict = field(default_factory=dict)

    def add(self, reason: str) -> None:
        self.counts[reason] = self.counts.get(reason, 0) + 1


def encode(payload: dict) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def sanitize(text: str, limit: int = 200) -> str:
    """Make peer text safe to log: no control characters, no newline forgery, bounded."""
    if not isinstance(text, str):
        return "<not-a-string>"
    cleaned = "".join(" " if ch in CONTROL_CHARS else ch for ch in text)
    cleaned = cleaned.replace("\n", " ").replace("\t", " ")
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned
