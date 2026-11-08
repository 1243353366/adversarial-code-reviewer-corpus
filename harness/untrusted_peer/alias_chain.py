"""Two aliases between the wire and the allocation, kept as a fixture pair.

SR-LENGTH-004 asked for a regression fixture for this exact shape: a peer-controlled
length that is not used directly but handed through intermediate names before reaching
`read_exact`. `naive` launders it twice and allocates. `guarded` carries the same two
aliases and refuses above the frame limit, which is the only thing that makes the shape
safe. The aliases are not the defect; the missing upper bound is.
"""
from __future__ import annotations

import struct

from .protocol import MAX_FRAME, ProtocolError


class NaiveAliasChain:
    """The defect: two renames, no bound. The peer still chooses the allocation."""

    def read_one(self, peer) -> bytes:
        header = peer.read_exact(4)
        (declared,) = struct.unpack(">I", header)
        hinted = declared          # alias one
        size = int(hinted)         # alias two
        return peer.read_exact(size)


class GuardedAliasChain:
    """The same aliases, bounded before the read. Cost of a 2 GB claim: four bytes."""

    def read_one(self, peer) -> bytes:
        header = peer.read_exact(4)
        (declared,) = struct.unpack(">I", header)
        hinted = declared
        size = int(hinted)
        if size > MAX_FRAME:
            raise ProtocolError("frame_too_large")
        if size == 0:
            raise ProtocolError("empty_frame")
        return peer.read_exact(size)
