"""Each test does the same attack twice: the naive listener must break, the hardened
one must refuse. A test that only shows the hardened version passing proves nothing
about whether the attack was real.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from harness.untrusted_peer import protocol as P
from harness.untrusted_peer.hardened import HardenedListener
from harness.untrusted_peer.naive import NaiveListener
from harness.untrusted_peer.protocol import ProtocolError, encode
from harness.untrusted_peer.peer import ScriptedPeer, framed, lying_frame

GOOD = {"type": "observation", "seq": 1, "note": "process 4211 listening on 8443"}


def hardened(clock=lambda: 0.0):
    return HardenedListener(clock=clock)


def test_a_good_frame_is_still_accepted():
    """No false positives. A listener that refuses everything is not secure, it is broken."""
    naive = NaiveListener(log=lambda _: None)
    assert naive.read_one(ScriptedPeer(encode(GOOD)))["seq"] == 1
    msg = hardened().read_one(ScriptedPeer(encode(GOOD)))
    assert (msg["seq"], msg["note"], msg["role"]) == (1, GOOD["note"], "peer")


def test_claimed_length_costs_the_listener_memory():
    """2 GB declared: the naive listener asks for all of it before reading a byte."""
    attack = lying_frame(2_000_000_000, b"{}")
    naive_peer = ScriptedPeer(attack)
    with pytest.raises(TimeoutError):
        NaiveListener(log=lambda _: None).read_one(naive_peer)
    assert naive_peer.largest_request == 2_000_000_000

    hardened_peer = ScriptedPeer(attack)
    with pytest.raises(ProtocolError) as err:
        hardened().read_one(hardened_peer)
    assert str(err.value) == "frame_too_large"
    assert hardened_peer.largest_request <= P.MAX_FRAME


def test_malformed_bytes_kill_the_naive_loop():
    body = b"\xff\xfe\x00{not json"
    with pytest.raises((UnicodeDecodeError, json.JSONDecodeError)):
        NaiveListener(log=lambda _: None).read_one(ScriptedPeer(framed(body)))

    listener = hardened()
    with pytest.raises(ProtocolError) as err:
        listener.read_one(ScriptedPeer(framed(body)))
    assert str(err.value) == "not_utf8"
    # and the listener is still usable afterwards
    assert listener.read_one(ScriptedPeer(encode(GOOD)))["seq"] == 1


def test_peer_cannot_promote_itself_to_operator():
    forged = dict(GOOD, role="operator")
    assert NaiveListener(log=lambda _: None).read_one(ScriptedPeer(encode(forged)))["role"] == "operator"

    listener = hardened()
    msg = listener.read_one(ScriptedPeer(encode(forged)))
    assert msg["role"] == "peer"
    assert listener.rejections.counts["forged_role_discarded"] == 1


def test_ansi_and_newline_injection_cannot_rewrite_the_log():
    hostile = dict(GOOD, note="ok\x1b[2J\x1b[H\r\n2026-11-08 ERROR audit disabled")
    naive_lines: list[str] = []
    NaiveListener(log=naive_lines.append).read_one(ScriptedPeer(encode(hostile)))
    assert "\x1b[2J" in naive_lines[0]

    listener = hardened()
    listener.read_one(ScriptedPeer(encode(hostile)))
    line = listener.lines[0]
    assert "\x1b" not in line and "\n" not in line and "\r" not in line
    assert line.startswith("peer said: ")


def test_unknown_field_and_wrong_type_are_refused_not_coerced():
    for bad, reason in (
        (dict(GOOD, cmd="rm -rf /"), "unknown_field"),
        (dict(GOOD, seq="1"), "bad_seq"),
        (dict(GOOD, type="command"), "bad_type"),
    ):
        with pytest.raises(ProtocolError) as err:
            hardened().read_one(ScriptedPeer(encode(bad)))
        assert str(err.value) == reason


def test_slow_trickle_runs_out_of_deadline_not_patience():
    """Two seconds per read against a five second budget: the third read must be refused."""
    now = {"t": 0.0}

    def clock():
        return now["t"]

    class Trickle(ScriptedPeer):
        def read_exact(self, n, deadline=None):
            now["t"] += 3.0            # each read costs the listener wall clock
            return super().read_exact(n, deadline)

    slow = Trickle(framed(b'{"type":"heartbeat","seq":1}'), clock=clock, timeout_after=1.0)
    listener = hardened(clock=clock)
    with pytest.raises(ProtocolError) as err:
        listener.read_one(slow)
    assert str(err.value) == "deadline_exceeded"
    assert listener.rejections.counts["deadline_exceeded"] == 1


def test_frame_flood_hits_a_quota():
    stream = b"".join(encode(GOOD) for _ in range(P.MAX_FRAMES_PER_CONNECTION + 5))
    naive = NaiveListener(log=lambda _: None)
    naive_peer = ScriptedPeer(stream)
    accepted = 0
    while True:
        try:
            naive.read_one(naive_peer)
            accepted += 1
        except TimeoutError:
            break
    assert accepted == P.MAX_FRAMES_PER_CONNECTION + 5

    listener = hardened()
    flood_peer = ScriptedPeer(stream)
    for _ in range(P.MAX_FRAMES_PER_CONNECTION):
        listener.read_one(flood_peer)
    with pytest.raises(ProtocolError) as err:
        listener.read_one(flood_peer)
    assert str(err.value) == "frame_quota_exhausted"


def test_receiver_never_executes_what_the_peer_sends():
    """The invariant that makes this module safe to run: no evaluation, ever."""
    root = pathlib.Path(__file__).resolve().parents[1] / "harness" / "untrusted_peer"
    banned = ("subprocess", "os.system", "eval(", "exec(", "popen", "shell=True")
    for f in sorted(root.glob("*.py")):
        text = f.read_text()
        for word in banned:
            assert word not in text, f"{f.name} contains {word}"
