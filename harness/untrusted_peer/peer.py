"""A peer that is not trusted, in the only sense that matters: it sends what it likes.

`read_exact` accepts a deadline so a test can drive the clock, and records the largest
allocation the listener asked for, which is how the unbound-allocation defect becomes
an assertion instead of an out-of-memory kill.
"""
from __future__ import annotations

import struct


class ScriptedPeer:
    def __init__(self, data: bytes = b"", clock=None, timeout_after: float | None = None):
        self.data = data
        self.pos = 0
        self.clock = clock or (lambda: 0.0)
        self.timeout_after = timeout_after
        self.largest_request = 0
        self.requests: list[int] = []

    def read_exact(self, n: int, deadline: float | None = None) -> bytes:
        self.requests.append(n)
        self.largest_request = max(self.largest_request, n)
        if deadline is not None and self.timeout_after is not None:
            if self.clock() >= deadline:
                raise TimeoutError("read deadline exceeded")
        if self.pos + n > len(self.data):
            raise TimeoutError("peer went quiet")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk


def framed(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def lying_frame(declared: int, sent: bytes) -> bytes:
    """Header claims one size, body supplies another. The listener decides which to trust."""
    return struct.pack(">I", declared) + sent
