#!/usr/bin/env python3
"""Observe what happened, then constrain what could explain it.

The layer above this one was an authority nobody checked: a person asserted `analyzer_guard_model`
and the classifier believed it. This module replaces that assertion with an execution. It runs the
code under review, records the values that reached the operation that matters, and compares the
result against a stated safety invariant. Evidence codes come from that comparison.

Three outputs, deliberately unequal in strength:

    observation      what the run did. Values, the operation they reached, whether the invariant held.
    counterfactual   what changed when one mechanism was altered. Correlation becomes causal only here.
    proposal         which mechanism accounts for the observations, with the experiment that would
                     settle it when more than one does.

A before/after result is not a root cause. R63 failing before and passing after says the change is
associated with the corrected behaviour; it does not say which semantic assumption was wrong, because
a patch can alter several things at once. So `witness()` can report:

    symptom gone, invariant still violated   -> the fix moved the symptom, not the defect
    two mechanisms, one observation set      -> both survive, with the discriminating run named
    invariant intact, no violation observed  -> no defect code at all, rather than a quiet pass

Classification stays downstream. This module proposes; `failure_classifier.py` classifies; the ledger
is still authored by hand.

    python tools/behavioral_witness.py                     # run the built-in scenarios
    python tools/behavioral_witness.py --json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LIMIT = 4096  # the frame bound the invariant is stated against


@dataclass
class Observation:
    """One execution. Facts only; no explanation lives in here."""

    label: str
    operation: str            # the operation that matters: read_exact, allocate, reject
    requested: int | None     # the value that reached it
    limit: int | None
    invariant_held: bool
    invariant_kind: str       # allocation_bound | boundary | guard | alias_depth
    symptom_visible: bool     # did the failure show up as an exception or a wrong answer
    over_limit: bool = False
    boundary_hit: bool = False
    quota_hit: bool = False
    detail: str = ""

    @property
    def violated(self) -> bool:
        return not self.invariant_held


@dataclass
class Counterfactual:
    """One mechanism altered, everything else left alone."""

    variant: str
    mutation: str
    violated: bool
    changed_outcome: bool

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Candidate:
    mechanism: str
    because: list[str] = field(default_factory=list)
    requires: str = ""       # the experiment that would confirm or eliminate it


@dataclass
class Witness:
    subject: str
    invariant: str
    observations: list[Observation] = field(default_factory=list)
    counterfactuals: list[Counterfactual] = field(default_factory=list)
    codes: list[str] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    classification: str = "insufficient_evidence"
    discriminator: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "subject": self.subject, "invariant": self.invariant,
            "observations": [asdict(o) for o in self.observations],
            "counterfactuals": [c.as_dict() for c in self.counterfactuals],
            "codes": self.codes, "candidates": [asdict(c) for c in self.candidates],
            "classification": self.classification, "discriminator": self.discriminator,
            "notes": self.notes,
        }


def codes_from(observations: list[Observation]) -> list[str]:
    """Evidence codes derived from what ran, not from a filename or an expected diagnosis."""
    codes = []
    for obs in observations:
        if obs.invariant_held:
            continue
        if obs.invariant_kind == "boundary":
            codes.append("observed_boundary_off_by_one")
        elif obs.invariant_kind == "allocation_bound":
            codes.append("observed_bound_not_enforced")
    return sorted(set(codes))


def candidates_from(observations: list[Observation], counterfactuals: list[Counterfactual]) -> list[Candidate]:
    """Mechanisms the observations support, with the experiment that would separate them.

    Two observations that differ only in the mechanism, and agree in outcome, cannot name a
    cause. Both candidates survive with the discriminating run requested, because picking one
    would be the same guess this whole layer exists to avoid.
    """
    out: list[Candidate] = []
    violating = [o for o in observations if o.violated]
    if not violating:
        return out

    masked = [o for o in violating if not o.symptom_visible]
    for obs in violating:
        if obs.invariant_kind == "allocation_bound" and obs.over_limit:
            if obs.quota_hit:
                # Both limits fired. Which one stopped the read cannot be told from this run,
                # so both survive rather than the one that sounds likelier.
                out.append(Candidate("bound_not_enforced",
                                     [f"{obs.label}: {obs.operation} received {obs.requested}, "
                                      f"limit {obs.limit}"]))
                out.append(Candidate("quota_exhaustion_masked_as_a_bound",
                                     [f"{obs.label}: a connection quota also applied to the same read"]))
            elif not obs.symptom_visible:
                out.append(Candidate("symptom_masking",
                                     [f"{obs.label}: requested {obs.requested} exceeds {obs.limit} "
                                      f"but nothing surfaced it"]))
            else:
                out.append(Candidate("bound_not_enforced",
                                     [f"{obs.label}: {obs.operation} received {obs.requested}, "
                                      f"limit {obs.limit}"]))
        if obs.invariant_kind == "boundary" and obs.boundary_hit:
            out.append(Candidate("boundary_condition_error",
                                 [f"{obs.label}: the boundary value itself was accepted"]))
        if obs.over_limit and obs.quota_hit:
            out.append(Candidate("quota_exhaustion_masked_as_a_bound",
                                 [f"{obs.label}: the read stopped, but a quota fired as well as the bound"]))
        if obs.invariant_kind == "alias_depth":
            out.append(Candidate("incomplete_data_flow",
                                 [f"{obs.label}: propagation stopped before the size"]))
    if masked and any(c.mechanism == "bound_not_enforced" for c in out) \
            and not any(o.quota_hit and o.over_limit for o in violating):
        out = [c for c in out if c.mechanism != "bound_not_enforced"]

    merged: dict[str, Candidate] = {}
    for cand in out:
        if cand.mechanism in merged:
            merged[cand.mechanism].because.extend(cand.because)
        else:
            merged[cand.mechanism] = cand
    out = list(merged.values())

    # Counterfactuals narrow the field only when altering one mechanism changes the outcome.
    moved = [c for c in counterfactuals if c.changed_outcome]
    if len(out) >= 2:
        for cand in out:
            cand.requires = (f"re-run with {out[0].mechanism} removed while holding "
                             f"{out[1].mechanism} fixed")
    elif out and not moved:
        out[0].requires = ("alter the suspected mechanism alone and re-run; without that, this "
                           "is an association, not a cause")
    return out


def witness(subject: str, invariant: str, runs: dict[str, object],
            mutations: dict[str, str] | None = None) -> Witness:
    """Run a baseline and its variants. The baseline is the key `baseline`."""
    w = Witness(subject=subject, invariant=invariant)
    mutations = mutations or {}
    observations = []
    for label, run in runs.items():
        obs = run()
        obs.label = label
        observations.append(obs)
    w.observations = observations
    base = next((o for o in observations if o.label == "baseline"), observations[0])
    for label, obs in ((o.label, o) for o in observations if o.label != base.label):
        w.counterfactuals.append(Counterfactual(
            variant=label, mutation=mutations.get(label, label),
            violated=obs.violated, changed_outcome=obs.invariant_held != base.invariant_held))
    w.codes = codes_from(observations)
    w.candidates = candidates_from(observations, w.counterfactuals)

    if not any(o.violated for o in w.observations):
        w.classification = "insufficient_evidence"
        w.notes.append("no invariant was violated in any run; there is nothing to classify")
        return w
    if not w.codes:
        w.classification = "insufficient_evidence"
        w.notes.append("an invariant was violated but no mechanism in the vocabulary accounts for it")
        return w
    if len(w.candidates) > 1:
        w.classification = "probable"
        w.discriminator = w.candidates[0].requires
        w.notes.append("more than one mechanism survives; the discriminator is required before this becomes a claim")
        return w
    if len(w.candidates) == 1:
        settled = any(c.changed_outcome for c in w.counterfactuals)
        w.classification = "supported" if settled else "probable"
        if not settled:
            w.discriminator = w.candidates[0].requires
        return w
    w.classification = "insufficient_evidence"
    w.notes.append("an invariant was violated but no mechanism in the vocabulary accounts for it")
    return w


# --- scenarios: real code where it exists, synthetic where the gate requires it ---------

class _Peer:
    """Records what was asked of it. `mask` suppresses the failure without fixing the size."""

    def __init__(self, declared, budget=LIMIT, mask=False):
        self.declared = declared
        self.budget = budget
        self.mask = mask
        self.requests: list[int] = []
        self._pending = True

    def read_exact(self, n, deadline=None):
        import struct

        self.requests.append(n)
        if self._pending:
            self._pending = False
            return struct.pack(">I", self.declared)
        if n > self.budget and not self.mask:
            raise MemoryError(n)
        return b"x" * min(n, 8)


def scenario_unbounded_frame():
    """Real fixture: two aliases, no bound, the peer chooses the allocation."""
    from harness.untrusted_peer.alias_chain import GuardedAliasChain, NaiveAliasChain

    def run(cls, label, mask=False):
        def go():
            peer = _Peer(2_000_000_000, mask=mask)
            err = None
            try:
                cls().read_one(peer)
            except MemoryError:
                err = "MemoryError"
            except Exception as exc:                      # a refusal is an outcome, not a crash
                err = type(exc).__name__
            asked = peer.requests[-1] if len(peer.requests) > 1 else None
            return Observation(
                label=label, operation="read_exact", requested=asked, limit=LIMIT,
                invariant_held=(asked is None or asked <= LIMIT), invariant_kind="allocation_bound",
                symptom_visible=err is not None, over_limit=bool(asked and asked > LIMIT),
                detail=f"requested {asked}; outcome {err or 'returned'}")
        return go

    return witness(
        "unbounded frame length", "a peer-chosen size never exceeds MAX_FRAME at the read",
        {"baseline": run(NaiveAliasChain, "baseline"), "guarded": run(GuardedAliasChain, "guarded")},
        {"guarded": "bound checked before the read"})


def scenario_off_by_one_quota():
    """Unfamiliar mechanism: not one of the nine recorded defects. A boundary, not a bound."""
    def reader(comparison):
        def go():
            accepted, cap = 5, 5
            # the peer's sixth frame is admitted when the comparison is wrong
            admitted = accepted + 1
            return Observation(
                label=comparison, operation="admit_frame", requested=admitted, limit=cap,
                invariant_held=not (comparison == ">" and admitted > cap),
                invariant_kind="boundary", symptom_visible=False, boundary_hit=comparison == ">",
                detail=f"accepted={accepted} cap={cap} admitted={admitted}")
        return go

    return witness(
        "frame quota boundary", "the connection admits at most MAX_FRAMES_PER_CONNECTION frames",
        {"baseline": reader(">"), "corrected": reader(">=")},
        {"corrected": "comparison changed from > to >= "})


def scenario_misleading_fix():
    """The symptom disappears because the transport swallows it. The size is unchanged."""
    from harness.untrusted_peer.alias_chain import NaiveAliasChain

    def run(mask):
        def go():
            peer = _Peer(2_000_000_000, mask=mask)
            err = None
            try:
                NaiveAliasChain().read_one(peer)
            except MemoryError:
                err = "MemoryError"
            asked = peer.requests[-1] if len(peer.requests) > 1 else None
            return Observation(
                label="masked" if mask else "baseline", operation="read_exact",
                requested=asked, limit=LIMIT,
                invariant_held=(asked is None or asked <= LIMIT), invariant_kind="allocation_bound",
                symptom_visible=err is not None, over_limit=bool(asked and asked > LIMIT),
                detail=f"requested {asked}; outcome {err or 'returned quietly'}")
        return go

    return witness(
        "unbounded frame length, symptom suppressed", "a peer-chosen size never exceeds MAX_FRAME",
        {"baseline": run(False), "masked": run(True)},
        {"masked": "transport caps the allocation; the requested size is unchanged"})


def scenario_competing():
    """Bound and quota both fire. One observation set, two surviving explanations."""
    def run(kind):
        def go():
            requested, cap = 9000, 5000
            return Observation(
                label=kind, operation="read_exact", requested=requested, limit=cap,
                invariant_held=False, invariant_kind="allocation_bound",
                symptom_visible=False, over_limit=True, quota_hit=True,
                detail="read stopped after 5000 bytes; both the frame bound and the connection quota applied")
        return go

    return witness(
        "frame stopped above the bound", "a peer-chosen size never exceeds MAX_FRAME",
        {"baseline": run("baseline"), "delayed": run("delayed")},
        {"delayed": "quota deferred so only the bound can stop the read"})


SCENARIOS = {
    "unbounded_frame": scenario_unbounded_frame,
    "frame_quota_boundary": scenario_off_by_one_quota,
    "symptom_suppressed": scenario_misleading_fix,
    "competing_explanations": scenario_competing,
}


def render(w: Witness) -> str:
    lines = [f"{w.subject}", f"  invariant: {w.invariant}"]
    for o in w.observations:
        lines.append(f"  {o.label:<9} {o.operation}({o.requested}) limit={o.limit} "
                     f"held={o.invariant_held} symptom={o.symptom_visible}  {o.detail}")
    for c in w.counterfactuals:
        lines.append(f"  change: {c.variant} ({c.mutation}) -> held={not c.violated} moved={c.changed_outcome}")
    lines.append(f"  codes: {w.codes or 'none'}")
    for cand in w.candidates:
        lines.append(f"  candidate: {cand.mechanism} :: {'; '.join(cand.because)}")
    lines.append(f"  classification: {w.classification}")
    if w.discriminator:
        lines.append(f"  discriminator: {w.discriminator}")
    for n in w.notes:
        lines.append(f"  note: {n}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Collect behavioural evidence before any diagnosis.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--only")
    args = parser.parse_args(argv)
    names = [args.only] if args.only else list(SCENARIOS)
    results = [SCENARIOS[n]() for n in names]
    print(json.dumps([r.as_dict() for r in results], indent=2) if args.json
          else "\n\n".join(render(r) for r in results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
