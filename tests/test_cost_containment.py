"""Adversarial cost containment: the ratio is the product, so the ratio gets the tests."""
from __future__ import annotations

import ast
import math
from pathlib import Path

import pytest

from harness.cost.containment import (
    OK,
    QUARANTINE,
    SYNTHETIC_REPLY,
    TERMINATE,
    THROTTLE,
    Budget,
    Guard,
    Sample,
    measure,
)

ROOT = Path(__file__).resolve().parent.parent
HONEST = Sample(request_bytes=200, response_bytes=150, cpu_seconds=0.0002)
EXPENSIVE = Sample(request_bytes=10, response_bytes=1_000_000, cpu_seconds=0.05, queue_growth=9)


def test_amplification_is_a_ratio_not_a_threshold():
    r = measure(Sample(request_bytes=100, response_bytes=400, cpu_seconds=0.001))
    assert r.bytes_amp == pytest.approx(4.0)
    assert r.cpu_amp == pytest.approx(10.0)  # 1000us of CPU over 100 request bytes


def test_an_empty_request_produces_a_number_not_a_nan():
    """A zero-byte request must not divide by zero, and must not slip past a '< limit' test."""
    r = measure(Sample(request_bytes=0, response_bytes=5000, cpu_seconds=0.01))
    assert not math.isnan(r.bytes_amp) and math.isfinite(r.bytes_amp)
    assert r.bytes_amp == pytest.approx(5000.0)
    assert r.breached(Budget())


def test_nan_cannot_hide_a_breach():
    """The mutation that motivated the floor: NaN comparisons are all False."""
    r = measure(Sample(request_bytes=0, response_bytes=1, cpu_seconds=0.0))
    assert not math.isnan(r.cpu_amp)
    assert r.cpu_amp == pytest.approx(0.0)


def test_honest_traffic_stays_ok_indefinitely():
    g = Guard()
    for _ in range(500):
        assert g.observe("honest", HONEST).action == OK
    assert g.counts["terminated"] == 0


def test_one_expensive_sample_throttles_but_does_not_kill():
    g = Guard()
    assert g.observe("peer", EXPENSIVE).action == THROTTLE
    assert g.observe("peer", HONEST).action == OK  # one strike, bought back by a cheap sample
    assert g.observe("peer", EXPENSIVE).action == THROTTLE  # escalation needs sustained cost


def test_escalation_is_by_count_not_by_severity():
    g = Guard()
    actions = [g.observe("peer", EXPENSIVE).action for _ in range(5)]
    assert actions == [THROTTLE, THROTTLE, QUARANTINE, QUARANTINE, TERMINATE]


def test_quarantine_answers_without_running_the_handler():
    g = Guard()
    for _ in range(3):
        d = g.observe("peer", EXPENSIVE)
    assert d.action == QUARANTINE
    assert d.run_handler is False
    assert d.reply == SYNTHETIC_REPLY


def test_termination_is_remembered_not_recomputed():
    g = Guard()
    for _ in range(5):
        g.observe("peer", EXPENSIVE)
    d = g.observe("peer", HONEST)  # an honest request from a terminated peer
    assert d.action == TERMINATE and d.run_handler is False


def test_denial_expires_after_the_ttl():
    now = {"t": 0.0}
    g = Guard(clock=lambda: now["t"])
    for _ in range(5):
        g.observe("peer", EXPENSIVE)
    now["t"] = 301.0
    assert g.observe("peer", HONEST).action == OK


def test_queue_growth_is_its_own_axis():
    """A slow consumer can be cheap per byte and still cost the listener a queue."""
    g = Guard()
    slow = Sample(request_bytes=1000, response_bytes=1000, cpu_seconds=0.0001, queue_growth=8)
    d = g.observe("slow", slow)
    assert d.action == THROTTLE and d.reasons == ("queue",)


def test_a_costly_peer_does_not_slow_an_honest_one():
    g = Guard()
    for _ in range(50):
        g.observe("honest", HONEST)
        g.observe("attacker", EXPENSIVE)
    assert g.observe("honest", HONEST).action == OK
    assert g.observe("attacker", EXPENSIVE).action in (QUARANTINE, TERMINATE)


def test_summary_publishes_the_metric():
    g = Guard()
    for _ in range(3):
        g.observe("peer", EXPENSIVE)
    row = next(r for r in g.summary() if r["conn"] == "peer")
    assert row["bytes_amp"] == pytest.approx(100000.0)
    assert row["breaches"] == 3


def test_containment_code_contains_no_execution_primitive_and_no_outbound_call():
    """Containment is local: no shell, no eval, no socket, no request to the peer."""
    banned_calls = {"eval", "exec", "system", "popen", "urlopen", "connect", "sendall"}
    banned_modules = {"subprocess", "socket", "requests", "urllib", "http"}
    for f in (ROOT / "harness" / "cost").glob("*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_calls, f"{f.name}: {node.func.id}"
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name.split(".")[0] for a in node.names]
                root = getattr(node, "module", "") or ""
                assert not (set(names) | {root.split(".")[0]}) & banned_modules, f"{f.name}: {names}"
