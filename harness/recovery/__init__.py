"""Apparent control versus verified control.

Taking a listener is not taking a host. This module refuses to call recovery complete on
the strength of the thing that was just compromised, and it treats "the probe could not
run" as blocking rather than clean, because that is exactly the state an adversary who
kept a second path would arrange.

Verdicts, strongest first: regressed, disputed, apparent, verified.
"""
from __future__ import annotations

from dataclasses import dataclass, field

REGRESSED = "regressed"
DISPUTED = "disputed"
APPARENT = "apparent"
VERIFIED = "verified"

PROCESS = "listener_process"
HOST_PROBE = "host_probe"
SESSIONS = "session_inventory"
CREDENTIALS = "credential_inventory"
LOG_SINK = "log_sink"

# Evidence gathered through the host we are trying to prove safe.
IN_BAND = "in_band"
# Evidence gathered through a channel the host cannot rewrite.
OUT_OF_BAND = "out_of_band"

CLEAN, DIRTY, UNAVAILABLE = "clean", "dirty", "unavailable"


@dataclass(frozen=True)
class Evidence:
    kind: str
    trust: str
    outcome: str
    round: int
    detail: str = ""


@dataclass(frozen=True)
class Claim:
    """What the operator asserts, plus the identity they expect to find."""

    asserts_control_of: str
    expected_pid: int
    expected_start_time: float


@dataclass
class Verdict:
    status: str
    reasons: list[str] = field(default_factory=list)
    blocking: list[str] = field(default_factory=list)

    @property
    def may_declare_recovery(self) -> bool:
        return self.status == VERIFIED


def assess(claim: Claim, evidence: list[Evidence], min_rounds: int = 2) -> Verdict:
    v = Verdict(APPARENT)

    def block(msg: str) -> None:
        v.blocking.append(msg)

    def dispute(msg: str) -> None:
        v.reasons.append(msg)

    by_kind: dict[str, list[Evidence]] = {}
    for e in evidence:
        by_kind.setdefault(e.kind, []).append(e)

    if not evidence:
        block("no evidence at all: control is asserted, not shown")
        return v

    # "Could not check" is not "checked and clean". This is the whole trap.
    for e in evidence:
        if e.outcome == UNAVAILABLE:
            block(f"{e.kind} could not be observed in round {e.round} ({e.detail or 'no detail'})")

    for e in evidence:
        if e.outcome == DIRTY:
            dispute(f"{e.kind} reported dirty in round {e.round}: {e.detail or 'no detail'}")

    for e in by_kind.get(PROCESS, []):
        if e.detail.startswith("pid="):
            pid, start = _parse_identity(e.detail)
            if pid != claim.expected_pid or abs(start - claim.expected_start_time) > 0.001:
                v.status = REGRESSED
                dispute(
                    f"listener identity changed (pid {pid} start {start}); the process we "
                    f"recovered is not the process now running"
                )

    sessions = by_kind.get(SESSIONS, [])
    for e in sessions:
        if e.trust != OUT_OF_BAND:
            block("session inventory came through the host under test, so it can be filtered")
        if e.outcome == DIRTY and "unattributed" in e.detail:
            dispute(f"a session nobody owns is present: {e.detail}")

    for e in by_kind.get(CREDENTIALS, []):
        if e.outcome == DIRTY and "unrevokable" in e.detail:
            dispute(f"a credential we cannot revoke through an authorised channel: {e.detail}")

    for e in by_kind.get(LOG_SINK, []):
        if e.outcome == DIRTY and "gap" in e.detail:
            dispute(f"log continuity broken, so the record has a hole: {e.detail}")

    if not any(e.trust == OUT_OF_BAND and e.outcome == CLEAN for e in evidence):
        block("no out-of-band evidence is clean, so every clean claim comes from the host itself")

    rounds = sorted({e.round for e in evidence})
    if len(rounds) < min_rounds:
        block(f"only {len(rounds)} observation round(s); recovery is a claim about persistence")

    v.reasons = v.reasons or ["every contracted check agrees"]
    if v.status == REGRESSED:
        return v
    if any(e.outcome == DIRTY for e in evidence):
        v.status = DISPUTED
        return v
    v.status = APPARENT if v.blocking else VERIFIED
    return v


def _parse_identity(detail: str) -> tuple[int, float]:
    parts = dict(p.split("=") for p in detail.split())
    return int(parts["pid"]), float(parts["start"])


def _is_fatal(reason: str) -> bool:
    return any(k in reason for k in ("unattributed", "unrevokable", "gap"))
