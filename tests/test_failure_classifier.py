"""The classifier proposes; it does not label, decide, or grade itself.

The tests that matter here are the negative ones. A classifier is only trustworthy to the
extent that it abstains, that its confidence means something specific, and that its
benchmark was written by someone other than itself.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import failure_classifier as fc  # noqa: E402
import failure_intelligence as fi  # noqa: E402


def by_id(finding_id: str) -> fc.Proposal:
    return next(p for p in fc.propose_for_ledger() if p.subject == finding_id)


# --- dimensions, not one label ------------------------------------------------------

def test_every_ledger_record_is_classified_without_abstaining():
    proposals = fc.propose_for_ledger()
    assert len(proposals) == 9
    assert [p.subject for p in proposals if p.abstained] == []


def test_the_two_bound_findings_are_one_component_but_two_mechanisms():
    """The reason the taxonomy is multidimensional: same cell, different mechanism."""
    bounds = by_id("SR-BOUND-001")
    guard = by_id("SR-BOUND-002")
    assert (bounds.component, bounds.mode) == (guard.component, guard.mode) == ("analyzer", "false_negative")
    assert bounds.mechanism == "semantic_model_error"
    assert guard.mechanism == "control_flow_reasoning_error"
    assert bounds.taxonomy_source == "arxiv_2408_13855"
    assert guard.taxonomy_source == "fse_2024"


def test_scope_and_propagation_are_distinguished_from_bounds():
    assert by_id("SR-SCOPE-001").mechanism == "scope_confinement_error"


def test_the_other_dimensions_land_where_the_evidence_points():
    assert (by_id("SR-LENGTH-004").component, by_id("SR-LENGTH-004").mode) == ("analyzer", "false_positive")
    assert by_id("SR-EXEMPT-001").component == "policy"
    assert by_id("SR-CI-001").component == "infrastructure"
    assert by_id("SR-POLICY-001").mode == "specification_ambiguity"
    assert (by_id("SR-COVERAGE-001").component, by_id("SR-COVERAGE-001").mode) == ("test", "missing_coverage")
    assert by_id("SR-ANALYZER-003").mode == "unverified_claim"


# --- abstention is an outcome, not a failure ----------------------------------------

def test_no_evidence_abstains():
    p = fc.propose("x", [])
    assert p.abstained and p.component is None and p.missing_information


def test_an_undefined_code_abstains_rather_than_coercing():
    p = fc.propose("x", ["looks_bad"])
    assert p.abstained and "unrecognised" in " ".join(p.missing_information)


def test_two_supported_mechanisms_abstain_as_ambiguous():
    p = fc.propose("x", ["expected_finding_actual_none", "reproduction_fails_without_fix",
                         "analyzer_bounds_model", "analyzer_guard_model"],
                   [{"kind": "reproduction", "ref": "R63"}])
    assert p.abstained and "more than one mechanism" in " ".join(p.missing_information)


def test_a_symptom_without_a_mechanism_abstains():
    p = fc.propose("x", ["expected_finding_actual_none"])
    assert p.abstained


# --- what confidence means here -----------------------------------------------------

def test_a_conclusive_diagnosis_is_probable_not_an_abstention():
    """Regression on a design error: no reproduction is not the same as no evidence."""
    p = fc.propose("x", ["control_not_exercised"])
    assert not p.abstained
    assert p.confidence == "probable"
    assert p.component == "infrastructure"


def test_supported_needs_a_failing_reproduction_and_a_surviving_witness():
    codes = ["expected_finding_actual_none", "reproduction_fails_without_fix", "analyzer_bounds_model"]
    assert fc.propose("x", codes, [{"kind": "reproduction", "ref": "R63"}]).confidence == "supported"
    assert fc.propose("x", codes).confidence == "probable"
    # a matching rule with a witness but no reproduction code: probable, not supported
    assert fc.propose("x", ["reported_site_cannot_contain_defect"],
                      [{"kind": "reproduction", "ref": "R66"}]).confidence == "probable"


def test_every_proposal_cites_a_taxonomy_source():
    for p in fc.propose_for_ledger():
        assert p.taxonomy_source in {"nist_sp800_231", "ieee_1044_2009", "arxiv_2408_13855",
                                    "fse_2024", "cwe"}, p.subject


# --- the vocabulary is closed and shared with the ledger ----------------------------

def test_every_ledger_code_is_in_the_closed_vocabulary():
    unknown = {c for f in fi.load() for c in f.evidence_codes} - set(fc.EVIDENCE_CODES)
    assert unknown == set()


def test_proposals_stay_inside_the_declared_dimensions():
    for p in fc.propose_for_ledger():
        assert p.component in fc.COMPONENTS
        assert p.mode in fc.MODES
        assert p.mechanism in fc.MECHANISMS


# --- the benchmark measures it, and the classifier does not grade itself -----------

def test_the_benchmark_labels_are_valid_and_independent():
    rows = fc.load_benchmark()
    assert len(rows) >= 15
    for row in rows:
        if not row.get("invalid_by_design"):
            assert set(row["evidence_codes"]) <= set(fc.EVIDENCE_CODES), row["case_id"]
        if row.get("expect") == "abstain":
            assert "expected_component" not in row
        else:
            assert row["expected_component"] in fc.COMPONENTS
            assert row["expected_mode"] in fc.MODES


def test_scores_against_the_labelled_set():
    report = fc.evaluate()
    assert report["cases"] == len(fc.load_benchmark())
    assert report["confusion"] == []
    for cell, stats in report["per_cell"].items():
        assert stats["correct"] == stats["proposed"], cell
        assert stats["precision"] == 1.0 and stats["recall"] == 1.0, cell
    assert report["abstention"]["missed"] == 0
    assert report["abstention"]["unnecessary"] == 0


def test_evaluating_does_not_rewrite_the_labels_or_the_ledger():
    paths = [fc.BENCHMARK, ROOT / "harness" / "findings.jsonl",
             ROOT / "harness" / "self_review_allow.txt"]
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    fc.evaluate()
    fc.propose_for_ledger()
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    assert before == after


def test_the_classifier_has_no_write_path_at_all():
    """It proposes. Editing a record is the reviewer's job, and closing one is nobody's."""
    tree = ast.parse((ROOT / "tools" / "failure_classifier.py").read_text())
    writes = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr in {"write_text", "write_bytes", "dump"}]
    assert writes == []


def test_an_ad_hoc_classification_is_reachable_from_the_command_line():
    assert fc.main(["--codes", '["threshold_outside_policy"]']) == 0
