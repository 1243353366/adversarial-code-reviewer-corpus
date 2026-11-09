"""Runs each hostile peer against both listeners and reports what happened.

Used by the CHANGELOG reproductions: a defect counts as reproduced only when the naive
listener breaks and the hardened one refuses for the stated reason.
"""
from __future__ import annotations

import json

from .hardened import HardenedListener
from .naive import NaiveListener
from .peer import ScriptedPeer, framed, lying_frame
from .protocol import MAX_FRAMES_PER_CONNECTION, encode

GOOD = {"type": "observation", "seq": 1, "note": "process 4211 listening on 8443"}


def _run(listener, data, clock=None):
    peer = ScriptedPeer(data, clock=clock or (lambda: 0.0), timeout_after=1.0)
    try:
        listener.read_one(peer)
        return "accepted", None
    except Exception as exc:  # the naive listener raises anything; the hardened one is specific
        return type(exc).__name__, exc


def attack(kind: str) -> tuple[tuple[str, object], tuple[str, object]]:
    """Return (naive_outcome, hardened_outcome) for one class of hostile peer."""
    if kind == "declared_length":
        data = lying_frame(2_000_000_000, b"{}")
    elif kind == "malformed_bytes":
        data = framed(b"\xff\xfe{not json")
    elif kind == "forged_role":
        data = encode(dict(GOOD, role="operator"))
    elif kind == "log_injection":
        data = encode(dict(GOOD, note="ok\x1b[2J\r\nERROR audit disabled"))
    elif kind == "unknown_field":
        data = encode(dict(GOOD, cmd="shutdown"))
    elif kind == "frame_flood":
        data = b"".join(encode(GOOD) for _ in range(MAX_FRAMES_PER_CONNECTION + 2))
    elif kind == "slow_trickle":
        data = framed(json.dumps(GOOD).encode())
    else:
        raise ValueError(f"unknown attack {kind!r}")

    now = {"t": 0.0}
    clock = (lambda: now["t"])

    if kind == "slow_trickle":
        class Trickle(ScriptedPeer):
            def read_exact(self, n, deadline=None):
                now["t"] += 3.0
                return super().read_exact(n, deadline)
        naive = _run(NaiveListener(log=lambda _: None), data, clock)
        naive_peer = Trickle(data, clock=clock, timeout_after=1.0)
        try:
            NaiveListener(log=lambda _: None).read_one(naive_peer)
            naive = ("accepted", None)
        except Exception as exc:
            naive = (type(exc).__name__, exc)
        now["t"] = 0.0
        peer = Trickle(data, clock=clock, timeout_after=1.0)
        try:
            HardenedListener(clock=clock).read_one(peer)
            hardened = ("accepted", None)
        except Exception as exc:
            hardened = (type(exc).__name__, exc)
        return naive, hardened

    if kind == "frame_flood":
        naive_peer = ScriptedPeer(data)
        naive_ok = 0
        naive_listener = NaiveListener(log=lambda _: None)
        while True:
            try:
                naive_listener.read_one(naive_peer)
                naive_ok += 1
            except Exception:
                break
        naive = (f"accepted_{naive_ok}", None)
        listener = HardenedListener(clock=lambda: 0.0)
        peer = ScriptedPeer(data)
        hardened_ok = 0
        while True:
            try:
                listener.read_one(peer)
                hardened_ok += 1
            except Exception as exc:
                hardened = (type(exc).__name__, exc)
                break
        return (naive[0], None), (f"accepted_{hardened_ok}_{hardened[0]}_{hardened[1]}", hardened[1])

    naive = _run(NaiveListener(log=lambda _: None), data, clock)
    hardened = _run(HardenedListener(clock=clock), data, clock)
    return naive, hardened


def _script_for(kind: str) -> bytes:
    """The bytes for one class of hostile peer, shared with the changelog reproductions."""
    data = {
        "declared_length": lying_frame(2_000_000_000, b"{}"),
        "malformed_bytes": framed(b"\xff\xfe{not json"),
        "forged_role": encode(dict(GOOD, role="operator")),
        "log_injection": encode(dict(GOOD, note="ok\x1b[2J\r\nERROR audit disabled")),
        "unknown_field": encode(dict(GOOD, cmd="shutdown")),
        "slow_trickle": framed(json.dumps(GOOD).encode()),
    }[kind]
    return data
