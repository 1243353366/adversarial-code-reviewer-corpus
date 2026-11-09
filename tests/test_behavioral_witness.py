"""The three gates the next layer has to pass before anyone trusts it.

Each one exists because the layer could otherwise become the new unverified authority: an
extractor that confidently names a mechanism on evidence that cannot support it. The tests are
written as adversarial cases rather than happy paths, because a behavioural extractor is only
worth having if it fails honestly.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

import behavioral_witness as bw  # noqa: E402
import failure_classifier as fc  # noqa: E402


# --- the observation itself --------------------------------------------------------

def test_an_observation_records_values_not_verdicts():
    w = bw.scenario_unbounded_frame()
    baseline = next(o for o in w.observations if o.label == "baseline")
    assert baseline.requested == 2_000_000_000
    assert baseline.limit == bw.LIMIT
    assert baseline.violated
    assert baseline.operation == "read_exact"


def test_a_refusal_is_recorded_as_an_outcome_not_a_crash():
    w = bw.scenario_unbounded_frame()
    guarded = next(o for o in w.observations if o.label == "guarded")
    assert guarded.invariant_held
    assert guarded.symptom_visible  # it raised, which is the correct visible behaviour


def test_codes_come_from_the_run_not_from_a_filename():
    w = bw.scenario_unbounded_frame()
    assert w.codes == ["observed_bound_not_enforced"]
    # the code names an observation the harness made; nothing in it refers to R63 or a test name
    assert not any(token in w.codes[0] for token in ("R63", "test_", "max"))


def test_the_module_never_reads_the_ledger_to_choose_a_mechanism():
    tree = ast.parse((ROOT / "tools" / "behavioral_witness.py").read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any("failure_intelligence" in name or "failure_classifier" in name for name in imported)


# --- gate 1: an unfamiliar defect --------------------------------------------------

def test_gate_unfamiliar_defect_is_classified_by_evidence_not_by_memory():
    """A boundary error, which is not one of the nine recorded defects."""
    w = bw.scenario_off_by_one_quota()
    assert w.codes == ["observed_boundary_off_by_one"]
    assert [c.mechanism for c in w.candidates] == ["boundary_condition_error"]
    assert w.classification == "supported"


def test_gate_unfamiliar_defect_reaches_the_taxonomy_with_a_source():
    proposal = fc.propose("frame_quota_boundary", ["observed_boundary_off_by_one"])
    assert (proposal.component, proposal.mode, proposal.mechanism) == (
        "product", "invariant_violation", "boundary_condition_error")
    assert proposal.taxonomy_source == "cwe"


# --- gate 2: a misleading reproduction ---------------------------------------------

def test_gate_symptom_suppression_is_not_accepted_as_a_fix():
    """The exception disappears; the peer-chosen size does not."""
    w = bw.scenario_misleading_fix()
    masked = next(o for o in w.observations if o.label == "masked")
    assert masked.symptom_visible is False          # the failing symptom is gone
    assert masked.violated is True                  # the invariant is not
    assert masked.requested == 2_000_000_000
    assert [c.mechanism for c in w.candidates] == ["symptom_masking"]
    assert w.classification == "probable"           # not "supported", and not a clean pass


def test_gate_symptom_suppression_never_yields_a_fixed_verdict():
    w = bw.scenario_misleading_fix()
    text = json.dumps(w.as_dict())
    assert "supported" not in text
    assert w.discriminator, "an unsettled claim must name the run that would settle it"


# --- gate 3: competing explanations ------------------------------------------------

def test_gate_two_plausible_causes_are_both_preserved():
    w = bw.scenario_competing()
    mechanisms = sorted(c.mechanism for c in w.candidates)
    assert mechanisms == ["bound_not_enforced", "quota_exhaustion_masked_as_a_bound"]
    assert w.classification == "probable"
    assert w.discriminator


def test_gate_competing_candidates_are_deduplicated_with_their_evidence():
    w = bw.scenario_competing()
    assert len(w.candidates) == len({c.mechanism for c in w.candidates})
    assert all(len(c.because) >= 1 for c in w.candidates)


# --- the distinction the user insisted on -----------------------------------------

def test_a_missing_witness_lowers_confidence_without_erasing_the_diagnosis():
    w = bw.witness("synthetic", "size stays under the limit",
                   {"baseline": lambda: bw.Observation(
                       label="baseline", operation="read_exact", requested=9000, limit=4096,
                       invariant_held=False, invariant_kind="allocation_bound",
                       symptom_visible=True, over_limit=True, detail="9000 > 4096")})
    assert w.codes == ["observed_bound_not_enforced"]
    assert w.candidates and w.candidates[0].mechanism == "bound_not_enforced"
    assert w.classification == "probable"      # no counterfactual: an association, not a cause
    assert w.discriminator


def test_no_violation_produces_no_code_and_no_claim():
    w = bw.witness("synthetic", "size stays under the limit",
                   {"baseline": lambda: bw.Observation(
                       label="baseline", operation="read_exact", requested=64, limit=4096,
                       invariant_held=True, invariant_kind="allocation_bound",
                       symptom_visible=False, detail="64 <= 4096")})
    assert w.codes == [] and w.candidates == [] and w.classification == "insufficient_evidence"


def test_an_unmapped_violation_abstains_instead_of_reaching_for_the_nearest_mechanism():
    w = bw.witness("synthetic", "handler stays responsive",
                   {"baseline": lambda: bw.Observation(
                       label="baseline", operation="loop", requested=None, limit=None,
                       invariant_held=False, invariant_kind="liveness", symptom_visible=False,
                       detail="the loop never yielded")})
    assert w.classification == "insufficient_evidence"
    assert "no mechanism in the vocabulary" in " ".join(w.notes)


# --- plumbing ---------------------------------------------------------------------

def test_every_scenario_runs_and_reports_its_invariant():
    for name, build in bw.SCENARIOS.items():
        w = build()
        assert w.invariant, name
        assert w.observations, name
        assert w.classification in {"supported", "probable", "insufficient_evidence"}, name


def test_running_the_witness_layer_writes_nothing():
    paths = [ROOT / "harness" / "findings.jsonl", ROOT / "harness" / "self_review_allow.txt"]
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    for build in bw.SCENARIOS.values():
        build()
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    assert before == after


def test_the_cli_runs_without_touching_the_ledger():
    assert bw.main(["--json"]) == 0
