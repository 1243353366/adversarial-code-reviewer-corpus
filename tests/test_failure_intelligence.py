"""The failure pipeline is a tool that proposes. These tests hold it to that.

Two things are checked beyond the obvious: that a finding cannot be filed with inference in
its evidence column, and that the component has no way to suppress a finding or declare one
fixed. A pipeline that can quieten its own input is a linter with a mute button.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

import failure_intelligence as fi  # noqa: E402


def record(**overrides) -> fi.Finding:
    base = dict(
        finding_id="SR-TEST-001", category="analyzer_defect", severity="high", confidence="observed",
        location="tools/self_review.py:1", rule="peer_length_before_bound",
        observed="A wire length reached an allocation.", why_matters="The peer chooses the size.",
        evidence=["a reproduction"], limitations=[], next_action="Add a fixture.",
    )
    base.update(overrides)
    return fi.Finding(**base)


# --- the ledger --------------------------------------------------------------------

def test_the_committed_ledger_loads_and_is_well_formed():
    findings = fi.load()
    assert len(findings) == 9
    assert len({f.finding_id for f in findings}) == len(findings)
    assert {f.category for f in findings} <= set(fi.CATEGORIES)


def test_hedging_in_the_observed_field_is_refused():
    """Facts only. 'may' is an inference, and it belongs in why_matters."""
    bad = record(observed="A peer may control the amount of data requested.")
    assert any("hedging" in p for p in bad.problems())


def test_a_finding_cannot_be_resolved_without_a_witness():
    bare = record(status="resolved", regression_test=None, reproduction=None, evidence=[])
    assert any("resolved without a witness" in p for p in bare.problems())
    witnessed = record(status="resolved", regression_test="tests/x.py::test_y", reproduction="R1")
    assert witnessed.problems() == []


def test_verified_confidence_requires_a_reproduction():
    claimed = record(confidence="verified", reproduction=None)
    assert any("verified confidence" in p for p in claimed.problems())


def test_a_rejection_needs_its_own_evidence():
    bare = record(status="rejected", evidence=[])
    assert any("rejected without evidence" in p for p in bare.problems())


def test_an_unknown_category_is_not_silently_accepted():
    assert any("unknown category" in p for p in record(category="vulnerability").problems())


# --- three views of one finding ----------------------------------------------------

def test_terminal_report_separates_facts_from_risk():
    text = fi.render([fi.load()[1]])
    order = ["Observed:", "Why it matters:", "Evidence:", "Limitations:", "Next action:"]
    positions = [text.index(label) for label in order]
    assert positions == sorted(positions)


def test_json_output_round_trips():
    findings = fi.load()
    parsed = json.loads(fi.to_json(findings))
    assert [p["finding_id"] for p in parsed] == [f.finding_id for f in findings]
    assert all(p["category"] in fi.CATEGORIES for p in parsed)


def test_sarif_output_is_consumable_by_code_scanning():
    findings = fi.load()
    sarif = json.loads(fi.to_sarif(findings))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"].startswith("assay")
    assert len(run["results"]) == len(findings)
    first = run["results"][0]
    assert first["ruleId"] in {r["id"] for r in run["tool"]["driver"]["rules"]}
    region = first["locations"][0]["physicalLocation"]["region"]
    assert isinstance(region["startLine"], int) and region["startLine"] >= 1
    levels = {f.severity for f in findings}
    produced = {r["level"] for r in run["results"]}
    assert produced <= {"error", "warning", "note"}
    if "high" in levels:
        assert "error" in produced


# --- intelligence ------------------------------------------------------------------

def test_repeated_misses_are_surfaced_per_rule():
    intel = fi.intelligence(fi.load())
    joined = " ".join(intel["analyzers_missing_defects"])
    assert "peer_length_before_bound" in joined


def test_a_load_bearing_assumption_becomes_review_agenda():
    """The PR#21 lesson: two findings, one wrong model of what a bound is."""
    intel = fi.intelligence(fi.load())
    agenda = " ".join(intel["review_agenda"])
    assert "syntax_implies_bound" in agenda
    assert "SR-BOUND-001" in agenda and "SR-BOUND-002" in agenda


def test_exemption_hotspots_are_reported_from_the_real_allowlist():
    intel = fi.intelligence(fi.load())
    assert any("naive.py" in h for h in intel["exemption_hotspots"])


def test_recurrence_is_detected_after_an_earlier_resolution():
    findings = [record(finding_id="SR-A-001", status="resolved",
                       regression_test="tests/x.py::t", reproduction="R1"),
                record(finding_id="SR-A-002", status="open")]
    assert any("SR-A-002" in r for r in fi.intelligence(findings)["recurrence"])


# --- evidence integrity ------------------------------------------------------------

def test_every_claimed_reproduction_exists():
    import repro

    known = {getattr(r, "id", getattr(r, "rid", "")) for r in repro.REGISTRY}
    claimed = {f.reproduction for f in fi.load() if f.reproduction}
    assert claimed <= known, claimed - known


def test_every_claimed_regression_test_exists():
    missing = []
    for finding in fi.load():
        if not finding.regression_test:
            continue
        path, _, name = finding.regression_test.partition("::")
        file = ROOT / path
        if not file.exists() or name not in file.read_text():
            missing.append(finding.regression_test)
    assert missing == []


# --- the guarantee the user asked for ----------------------------------------------

def test_the_component_cannot_suppress_or_close_anything():
    """No suppression API, and, stronger: no write reaching the exemption list."""
    for forbidden in ("suppress", "mark_fixed", "resolve_finding", "accept", "dismiss"):
        assert not hasattr(fi, forbidden), forbidden

    tree = ast.parse((ROOT / "tools" / "failure_intelligence.py").read_text())
    writes = [node for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr in {"write_text", "write_bytes"}]
    assert writes, "the module should write its SARIF output somewhere"
    for call in writes:
        target = ast.unparse(call.func.value)
        assert "allow" not in target.lower(), f"write path touches an exemption file: {target}"
        assert "LEDGER" not in target, "the ledger is authored by hand and reviewed, not written by the tool"


def test_running_every_view_changes_nothing_on_disk():
    targets = [ROOT / "harness" / "findings.jsonl", ROOT / "harness" / "self_review_allow.txt"]
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in targets}
    findings = fi.load()
    fi.render(findings), fi.to_json(findings), fi.to_sarif(findings), fi.intelligence(findings)
    fi.main(["--intel"])
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in targets}
    assert before == after


def test_check_fails_on_an_open_high_finding(tmp_path, monkeypatch):
    ledger = tmp_path / "findings.jsonl"
    ledger.write_text(json.dumps(fi.asdict(record())) + "\n")
    monkeypatch.setattr(fi, "LEDGER", ledger)
    assert fi.main(["--check"]) == 1


def test_check_passes_when_no_high_finding_is_open(monkeypatch):
    assert fi.main(["--check"]) == 0
