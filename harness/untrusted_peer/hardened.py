"""Handling a peer's bytes as hostile input.

The design rule: nothing the peer sends can change what the listener is, how much it
spends, or how its logs read. The peer supplies data; the listener supplies meaning.

Order matters. Cheapest check first, because the expensive ones are the ones an
attacker wants you to reach:

  1. length bound before allocating      -> a claimed 2 GB costs four bytes to reject
  2. wall clock before reading           -> a trickle costs one deadline, not a thread
  3. decode strictly                     -> malformed bytes are refused, not guessed
  4. schema before use                   -> unknown keys and types never reach logic
  5. role from local state               -> the peer's self-description is discarded
  6. sanitize before logging             -> the log cannot be rewritten by the peer
"""
from __future__ import annotations

import json
import struct

from .protocol import (
    ALLOWED_KEYS,
    ALLOWED_TYPES,
    MAX_FRAME,
    MAX_FRAMES_PER_CONNECTION,
    MAX_WALL_SECONDS,
    ProtocolError,
    Rejections,
    sanitize,
)


class HardenedListener:
    def __init__(self, clock, log=None):
        self.clock = clock
        self.rejections = Rejections()
        self.accepted = 0
        self.lines: list[str] = []
        self._log = log or self.lines.append

    def _read(self, peer, n: int, deadline: float) -> bytes:
        """A peer that goes quiet is a rejection, not an exception that kills the loop."""
        try:
            return peer.read_exact(n, deadline)
        except TimeoutError:
            self._reject("deadline_exceeded")

    def _reject(self, reason: str) -> None:
        self.rejections.add(reason)
        raise ProtocolError(reason)

    def read_one(self, peer) -> dict:
        if self.accepted >= MAX_FRAMES_PER_CONNECTION:
            self._reject("frame_quota_exhausted")

        deadline = self.clock() + MAX_WALL_SECONDS
        header = self._read(peer, 4, deadline)
        (declared,) = struct.unpack(">I", header)

        # Bounded before allocation. The four bytes have already cost the peer a write;
        # they must not cost the listener the memory it asks for.
        if declared > MAX_FRAME:
            self._reject("frame_too_large")
        if declared == 0:
            self._reject("empty_frame")

        body = self._read(peer, declared, deadline)

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            self._reject("not_utf8")
        try:
            msg = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            self._reject("not_json")
        if not isinstance(msg, dict):
            self._reject("not_an_object")

        unknown = set(msg) - ALLOWED_KEYS - {"role"}
        if unknown:
            self._reject("unknown_field")
        if msg.get("type") not in ALLOWED_TYPES:
            self._reject("bad_type")
        if not isinstance(msg.get("seq"), int):
            self._reject("bad_seq")

        # The peer's claimed role is not read. It is recorded as a forgery attempt and
        # discarded; the connection's role comes from local state.
        if "role" in msg:
            self.rejections.add("forged_role_discarded")

        note = sanitize(msg.get("note", ""))
        self.accepted += 1
        self._log(f"peer said: {note}")
        return {"type": msg["type"], "seq": msg["seq"], "note": note, "role": "peer"}
