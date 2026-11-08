"""The fixture SR-LENGTH-004 asked for: a length laundered through two aliases.

Both halves are exercised, because a fixture that only shows the defect reproducing tells
you nothing about whether the fix is the thing that stopped it. The analyzer is checked
against the same file, so the static rule and the runtime behaviour have to agree about
which half is which.
"""
from __future__ import annotations

import ast
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from harness.untrusted_peer.alias_chain import GuardedAliasChain, NaiveAliasChain  # noqa: E402
from harness.untrusted_peer.protocol import MAX_FRAME, ProtocolError  # noqa: E402
import self_review as SR  # noqa: E402

HUGE = 2_000_000_000
MEMORY_BUDGET = 1 << 20


class RecordingPeer:
    """Records every size asked of it, and treats a request over budget as an allocation."""

    def __init__(self, declared: int):
        self.declared = declared
        self.requests: list[int] = []
        self._header_pending = True

    def read_exact(self, n: int, deadline: float | None = None) -> bytes:
        self.requests.append(n)
        if self._header_pending:
            self._header_pending = False
            return struct.pack(">I", self.declared)
        if n > MEMORY_BUDGET:
            raise MemoryError(f"allocating {n} bytes for a peer-chosen size")
        return b"x" * n


def test_the_naive_half_allocates_whatever_the_peer_declares():
    """The defect, reproduced: two aliases, no bound, the allocation happens."""
    peer = RecordingPeer(HUGE)
    with pytest.raises(MemoryError):
        NaiveAliasChain().read_one(peer)
    assert peer.requests == [4, HUGE]


def test_the_guarded_half_refuses_before_asking_for_memory():
    peer = RecordingPeer(HUGE)
    with pytest.raises(ProtocolError) as caught:
        GuardedAliasChain().read_one(peer)
    assert str(caught.value) == "frame_too_large"
    assert peer.requests == [4]  # the header, and nothing after it


def test_the_guarded_half_still_accepts_a_legal_frame():
    peer = RecordingPeer(64)
    assert GuardedAliasChain().read_one(peer) == b"x" * 64


def test_a_zero_length_frame_is_refused_rather_than_read():
    peer = RecordingPeer(0)
    with pytest.raises(ProtocolError) as caught:
        GuardedAliasChain().read_one(peer)
    assert str(caught.value) == "empty_frame"
    assert peer.requests == [4]


def test_the_analyzer_agrees_with_the_runtime_about_which_half_is_broken():
    """One finding, in the naive half, and none for the guarded one carrying the same aliases."""
    path = ROOT / "harness" / "untrusted_peer" / "alias_chain.py"
    findings = SR.rule_length_before_bound(ast.parse(path.read_text()), str(path.relative_to(ROOT)))
    assert len(findings) == 1
    source = path.read_text().splitlines()
    assert "NaiveAliasChain" in "\n".join(source[: findings[0].line])
    assert "size" in findings[0].why


def test_listener_does_not_decode_the_wire():
    """SR-LENGTH-004 was filed against listener.py:84, which is not a read_exact site.

    The listener handles envelopes whose bytes were already parsed; wire decoding lives in
    untrusted_peer. If that separation ever changes, this test is the place it surfaces, and
    the length rule will have to be pointed at the new site.
    """
    source = (ROOT / "harness" / "provenance" / "listener.py").read_text()
    assert "read_exact" not in source
    assert "struct.unpack" not in source
