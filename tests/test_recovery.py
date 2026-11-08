"""Apparent control versus verified control: what may be declared, and when."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from harness.recovery import (
    APPARENT,
    CLEAN,
    CREDENTIALS,
    DIRTY,
    DISPUTED,
    HOST_PROBE,
    IN_BAND,
    LOG_SINK,
    OUT_OF_BAND,
    PROCESS,
    REGRESSED,
    SESSIONS,
    UNAVAILABLE,
    VERIFIED,
    Claim,
    Evidence,
    assess,
)

CLAIM = Claim(asserts_control_of="listener", expected_pid=101, expected_start_time=5000.0)
IDENTITY = "pid=101 start=5000.0"


def full(rounds=(1, 2)):
    """Everything clean, two rounds, mix of in-band and out-of-band."""
    out = []
    for r in rounds:
        out += [
            Evidence(PROCESS, IN_BAND, CLEAN, r, IDENTITY),
            Evidence(HOST_PROBE, OUT_OF_BAND, CLEAN, r),
            Evidence(SESSIONS, OUT_OF_BAND, CLEAN, r),
            Evidence(CREDENTIALS, OUT_OF_BAND, CLEAN, r),
            Evidence(LOG_SINK, OUT_OF_BAND, CLEAN, r),
        ]
    return out


def test_two_clean_rounds_with_out_of_band_evidence_is_verified():
    v = assess(CLAIM, full())
    assert v.status == VERIFIED
    assert v.may_declare_recovery


def test_process_control_alone_is_apparent_never_verified():
    v = assess(CLAIM, [Evidence(PROCESS, IN_BAND, CLEAN, 1, IDENTITY)])
    assert v.status == APPARENT
    assert any("out-of-band" in b for b in v.blocking)


def test_a_probe_that_could_not_run_blocks_rather_than_passes():
    """The trap: 'could not check' must never be recorded as 'checked, nothing found'."""
    v = assess(CLAIM, full() + [Evidence(LOG_SINK, OUT_OF_BAND, UNAVAILABLE, 2, "sink unreachable")])
    assert v.status == APPARENT
    assert any("could not be observed" in b for b in v.blocking)


def test_an_unattributed_session_disputes_even_a_clean_picture():
    v = assess(CLAIM, full() + [Evidence(SESSIONS, OUT_OF_BAND, DIRTY, 2, "one unattributed session from 10.0.0.9")])
    assert v.status == DISPUTED


def test_in_band_session_inventory_is_not_evidence_of_absence():
    ev = [e for e in full() if e.kind != SESSIONS] + [
        Evidence(SESSIONS, IN_BAND, CLEAN, 1),
        Evidence(SESSIONS, IN_BAND, CLEAN, 2),
    ]
    v = assess(CLAIM, ev)
    assert v.status == APPARENT
    assert any("filtered" in b for b in v.blocking)


def test_listener_restart_by_pid_reuse_is_caught_by_start_time():
    ev = full() + [Evidence(PROCESS, IN_BAND, CLEAN, 2, "pid=101 start=9000.0")]
    v = assess(CLAIM, ev)
    assert v.status == REGRESSED


def test_new_pid_is_regression_not_recovery():
    v = assess(CLAIM, full() + [Evidence(PROCESS, IN_BAND, CLEAN, 2, "pid=202 start=5000.0")])
    assert v.status == REGRESSED


def test_unrevokable_credential_disputes():
    v = assess(CLAIM, full() + [Evidence(CREDENTIALS, OUT_OF_BAND, DIRTY, 2, "unrevokable key id 7")])
    assert v.status == DISPUTED


def test_log_gap_disputes():
    v = assess(CLAIM, full() + [Evidence(LOG_SINK, OUT_OF_BAND, DIRTY, 2, "gap of 40 minutes")])
    assert v.status == DISPUTED


def test_dirty_host_probe_disputes():
    v = assess(CLAIM, full() + [Evidence(HOST_PROBE, OUT_OF_BAND, DIRTY, 2, "second admin key present")])
    assert v.status == DISPUTED


def test_a_single_round_is_never_verification():
    v = assess(CLAIM, full(rounds=(1,)))
    assert v.status == APPARENT
    assert any("observation round" in b for b in v.blocking)


def test_regression_outranks_every_clean_signal():
    ev = full() + [Evidence(PROCESS, IN_BAND, CLEAN, 2, "pid=999 start=1.0")]
    assert assess(CLAIM, ev).status == REGRESSED


@pytest.mark.parametrize("status", [APPARENT, DISPUTED, REGRESSED])
def test_only_verified_may_declare_recovery(status):
    v = assess(CLAIM, [Evidence(PROCESS, IN_BAND, CLEAN, 1, IDENTITY)])
    v.status = status
    assert not v.may_declare_recovery


def test_empty_evidence_is_apparent_with_a_reason():
    v = assess(CLAIM, [])
    assert v.status == APPARENT
    assert v.blocking


def test_module_touches_no_network_and_runs_nothing():
    tree = ast.parse(Path("harness/recovery/__init__.py").read_text())
    banned = {"subprocess", "socket", "shutil", "eval", "exec"}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    imports = {
        a.name.split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in n.names
    }
    assert not (banned & (names | attrs | imports))
