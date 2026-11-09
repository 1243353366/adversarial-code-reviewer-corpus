"""The zero targets and the effort numbers, tested by planting failures rather than by asserting zeros.

A test that asserts `containment_failures == 0` when the value is a literal in the source proves
nothing. These tests build a violating module and a leaking decoy and require the counters to move,
so a zero from the real package means the audit looked and found nothing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEC = ROOT / "harness" / "deception"

import effort  # noqa: E402
import hellbox as hb  # noqa: E402
import mirror as mx  # noqa: E402


# --- the audit can fail, which is what makes a zero mean something -------------------

def test_the_audit_catches_a_module_that_could_reach_the_network(tmp_path):
    (tmp_path / "leaky.py").write_text(
        "import socket\nimport subprocess\n\ndef dial():\n    return socket.socket()\n")
    result = effort.audit_package(tmp_path)
    assert result["unauthorized_outbound"] > 0
    assert result["production_exposure"] > 0
    assert "leaky.py" in result["violating_modules"]


def test_the_audit_catches_a_real_file_open(tmp_path):
    (tmp_path / "reader.py").write_text("def read():\n    return open('/etc/passwd').read()\n")
    result = effort.audit_package(tmp_path)
    assert result["unexplained_file_access"] == 1
    assert "reader.py" in result["violating_modules"]


def test_the_real_package_reports_zero_because_it_has_no_such_capability():
    result = effort.audit_package(DEC)
    assert result["production_exposure"] == 0
    assert result["unauthorized_outbound"] == 0
    assert result["unexplained_file_access"] == 0
    assert set(result["modules_audited"]) >= {"hellbox.py", "mirror.py", "aws_intel.py"}


def test_the_audit_does_not_audit_itself_away():
    """effort.py is excluded from its own count, so the exclusion has to be visible."""
    assert "effort.py" not in effort.audit_package(DEC)["modules_audited"]
    assert "effort.py" in {p.name for p in DEC.glob("*.py")}


# --- the independent axis -----------------------------------------------------------

def _session_with_decoy(marked: bool):
    box = mx.Mirror()
    session = box.connect("198.51.100.44:41412")
    # the mirror serves from env.files, not the base synthetic tree
    session.env.files["/var/www/app/.env"] = (
        "DB_PASSWORD=decoy-not-a-credential\n" if marked else "DB_PASSWORD=hunter2\n")
    session.send("cat /var/www/app/.env\n")
    return session


def test_a_marked_decoy_is_not_misidentified():
    report = effort.artifact_misidentification([_session_with_decoy(marked=True)])
    assert report["decoy_artifacts_served"] == 1
    assert report["misidentified_as_genuine"] == 0


def test_an_unmarked_decoy_is_counted_as_misidentified():
    report = effort.artifact_misidentification([_session_with_decoy(marked=False)])
    assert report["misidentified_as_genuine"] == 1


def test_the_real_traffic_serves_decoys_and_misidentifies_none():
    box = mx.Mirror()
    session = box.connect("198.51.100.45:41412")
    session.send(hb.DEMO)
    report = effort.artifact_misidentification([session])
    assert report["decoy_artifacts_served"] > 0
    assert report["misidentified_as_genuine"] == 0


# --- effort versus benefit, kept apart ----------------------------------------------

def test_effort_and_benefit_are_reported_separately_with_a_caveat():
    box = mx.Mirror()
    session = box.connect("198.51.100.46:41412")
    session.send(hb.DEMO)
    report = effort.report([session])
    assert "time_in_deception_seconds" in report["attacker_effort"]["measured"]
    assert "sessions_kept_off_production" in report["defensive_benefit"]["measured"]
    assert "not money lost" in report["attacker_effort"]["inferred"]["caveat"]
    assert report["defensive_benefit"]["zero_targets"]


def test_repeated_reconnaissance_is_counted_not_guessed():
    box = mx.Mirror()
    session = box.connect("198.51.100.47:41412")
    session.send("whoami\nwhoami\nwhoami\nls\n")
    report = effort.attacker_effort([session])
    assert report["measured"]["repeated_reconnaissance_attempts"] == 2


def test_dwell_time_is_a_measurement_and_its_interpretation_is_labelled():
    box = mx.Mirror()
    session = box.connect("198.51.100.48:41412")
    session.send("pwd\n")
    report = effort.attacker_effort([session])
    assert report["measured"]["time_in_deception_seconds"] >= 0
    assert report["inferred"]["basis"].startswith("dwell time")


# --- the verdict model --------------------------------------------------------------

def test_probes_return_three_valued_verdicts_not_booleans():
    box = mx.Mirror()
    verdict = mx.probe_canary(box.connect("198.51.100.49:41412"))
    assert verdict.outcome in {mx.SYNTHETIC, mx.GENUINE, mx.INCONCLUSIVE}
    assert verdict.reason


def test_a_probe_with_no_measurement_is_inconclusive_not_negative():
    box = mx.Mirror()
    session = box.connect("198.51.100.50:41412")
    session.closed, session.close_reason = True, "closed_before_probe"
    verdict = mx.probe_timing(session)
    assert verdict.outcome == mx.INCONCLUSIVE


def test_the_two_probabilities_are_declared_a_partition():
    row = mx.evaluate(True, True, sessions=2)
    partition = row["verdict_partition"]
    assert partition["synthetic"] + partition["genuine"] + partition["inconclusive"] == 7
    assert "sum to one by construction" in partition["note"]
    assert row["detection_rate"] + row["false_identification_rate"] == 1.0


# --- the report end to end ----------------------------------------------------------

def test_measurement_carries_verdicts_effort_and_counted_zeros():
    data = mx.measure(sessions=2)
    row = data["stateful_mirror"]
    assert {v["outcome"] for v in row["verdicts"]} <= {mx.SYNTHETIC, mx.GENUINE, mx.INCONCLUSIVE}
    assert row["detection_rate"] < data["naive_mirror"]["detection_rate"]
    assert row["false_identification_rate"] > data["naive_mirror"]["false_identification_rate"]
    assert data["effort"]["containment"]["production_exposure"] == 0
    assert data["effort"]["artifact_integrity"]["misidentified_as_genuine"] == 0
    json.dumps(data)


def test_effort_cli_runs_as_a_process():
    import subprocess

    result = subprocess.run([sys.executable, str(DEC / "effort.py"), "--json"],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-300:]
    payload = json.loads(result.stdout)
    assert payload["containment"]["production_exposure"] == 0
