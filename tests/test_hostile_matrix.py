"""The security invariant, tested adversarially rather than assumed.

Invariant: no unauthorized change to a protected file causes repository code to execute before
the change is detected. The matrix proves ordering with a canary and proves detection with exit
status. A green matrix is evidence about these ten cases, not proof the trust roots are sound.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import hostile_matrix as hm  # noqa: E402


def test_every_mutation_is_detected_before_any_repository_code_runs():
    report = hm.run(verbose=False)
    rows = report["rows"]
    mutations = [r for r in rows if r["mutation"] != "clean_control"]
    assert report["ok"] is True, [r for r in rows if not r["ok"]]
    assert len(mutations) >= 9
    for row in mutations:
        assert row["detected"] is True, row
        assert row["code_executed"] is False, row
        assert row["stopped_at"] <= 2, row


def test_the_clean_tree_still_passes_and_reaches_execution():
    report = hm.run(verbose=False)
    clean = [r for r in report["rows"] if r["mutation"] == "clean_control"][0]
    assert clean["stopped_at"] == 3
    assert clean["code_executed"] is True


def test_combined_mutations_are_covered_not_just_single_ones():
    names = [r["mutation"] for r in hm.run(verbose=False)["rows"]]
    combined = [n for n in names if "_and_" in n or n == "everything"]
    assert len(combined) >= 3, names


def test_the_canary_actually_fires():
    """Without this, every 'not executed' above would fit a canary that never worked."""
    assert hm.canary_works() is True


def test_replacing_the_verifier_is_caught_by_the_digest_not_by_its_own_report():
    row = [r for r in hm.run(verbose=False)["rows"] if r["mutation"] == "replace_verifier"][0]
    assert row["stopped_at"] == 1
    assert "verifier_digest" in row["reason"]


def test_the_workflow_orders_verification_before_execution():
    text = (ROOT / ".github" / "workflows" / "validate.yml").read_text()
    assert hm.workflow_problems(text) == []


def test_the_ordering_check_catches_a_workflow_that_installs_first():
    bad = """
name: validate
jobs:
  corpus:
    steps:
      - name: Install dev dependencies
        run: pip install -r requirements-dev.txt
      - name: Verify repository integrity
        run: python tools/integrity.py verify
"""
    assert hm.workflow_problems(bad)


def test_the_matrix_runs_as_a_process_and_reports_json():
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "hostile_matrix.py"), "--json"],
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout[-400:] + result.stderr[-400:]
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
