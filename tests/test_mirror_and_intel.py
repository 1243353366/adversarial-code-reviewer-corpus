"""The mirror's honesty and the correlator's restraint, both measured rather than asserted.

Two claims are under test. That per-session variation actually changes what a probe strategy
detects, which is a number rather than an opinion. And that the AWS correlator never upgrades a
provider address into an ownership claim, no matter how suggestive the port set looks.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEC = ROOT / "harness" / "deception"

import aws_intel as ai  # noqa: E402
import mirror as mx  # noqa: E402


# --- the mirror is a host, not a lookup table --------------------------------------

def test_a_session_has_a_coherent_host_behind_it():
    box = mx.Mirror()
    s = box.connect("198.51.100.20:41412")
    host = s.send("hostname\n")[0].response.strip()
    uname = s.send("uname -a\n")[0].response
    assert host in uname
    assert host == s.env.hostname


def test_the_environment_is_not_thin():
    box = mx.Mirror()
    s = box.connect("198.51.100.21:41412")
    assert s.send("ps\n")[0].response.count("\n") >= 10
    assert s.send("cat /etc/passwd\n")[0].response.count("\n") >= 6
    assert s.send("ss\n")[0].response.count("LISTEN") >= 2


def test_writes_persist_inside_the_session():
    box = mx.Mirror()
    s = box.connect("198.51.100.22:41412")
    s.send("echo marker123 > /tmp/probe\n")
    assert "marker123" in s.send("cat /tmp/probe\n")[0].response
    s.send("rm /tmp/probe\n")
    assert "No such file" in s.send("cat /tmp/probe\n")[0].response


def test_state_survives_a_reconnect_on_another_port():
    box = mx.Mirror()
    first = box.connect("198.51.100.23:41412")
    first.send("echo kept > /tmp/breadcrumb\n")
    first.send("cd /var/www/app\n")
    second = box.connect("198.51.100.23:51000")
    assert second is first
    assert "kept" in second.send("cat /tmp/breadcrumb\n")[0].response
    assert second.env.cwd == "/var/www/app"


def test_two_sources_meet_different_hosts():
    box = mx.Mirror(variation=True)
    a = box.connect("198.51.100.30:41412").send("hostname\n")[0].response
    b = box.connect("198.51.100.31:41412").send("hostname\n")[0].response
    assert a != b


def test_without_variation_two_sources_meet_an_identical_host():
    """The fingerprint the metric is supposed to reveal."""
    box = mx.Mirror(variation=False)
    a = box.connect("198.51.100.32:41412").env
    b = box.connect("198.51.100.33:41412").env
    assert (a.hostname, a.kernel, a.processes) == (b.hostname, b.kernel, b.processes)


# --- the measurement ---------------------------------------------------------------

def test_measurement_reports_both_configurations_with_the_required_fields():
    report = mx.measure(sessions=2)
    for key in ("naive_mirror", "stateful_mirror"):
        row = report[key]
        for field in ("detection_rate", "false_identification_rate", "commands_before_first_detection",
                      "session_consistency", "verdict_partition", "inconclusive", "detected", "undetected"):
            assert field in row, (key, field)


def test_stateful_mirror_is_harder_to_identify_than_a_naive_one():
    report = mx.measure(sessions=3)
    assert report["stateful_mirror"]["detection_rate"] < report["naive_mirror"]["detection_rate"]
    assert "cross_session" in report["naive_mirror"]["detected"]
    assert "cross_session" not in report["stateful_mirror"]["detected"]


def test_the_surviving_tells_are_named_rather_than_hidden():
    report = mx.measure(sessions=2)
    disclosed = set(report["structural_tells"])
    assert {"canary", "no_outbound", "timing"} <= disclosed
    assert disclosed <= set(report["stateful_mirror"]["detected"])
    # containment is a counted audit, not a literal in the row
    assert report["effort"]["containment"]["production_exposure"] == 0


def test_continuity_within_a_session_is_preserved():
    assert mx.evaluate(True, True, sessions=2)["session_consistency"] is True


# --- the correlator refuses to overclaim ------------------------------------------

def test_ownership_is_never_established():
    report = ai.correlate(ai.Facts(source_ip="52.14.203.77", session_count=5,
                                   source_ports=[4444, 1337], tls_offered=False))
    assert report.ownership == "not established"
    assert report.as_dict()["ownership"] == "not established"


def test_a_provider_address_does_not_become_attribution():
    report = ai.correlate(ai.Facts(source_ip="52.14.203.77"))
    assert "address space only" in report.provider_observed
    assert "compromised customer instance" in " ".join(report.alternative_explanations)


def test_a_suggestive_port_set_alone_stays_low_confidence():
    report = ai.correlate(ai.Facts(source_ip="203.0.113.5", source_ports=[4444, 1337]))
    assert report.confidence in {"low", "insufficient_evidence"}
    assert report.ownership == "not established"


def test_confidence_rises_with_independent_evidence():
    weak = ai.correlate(ai.Facts(source_ip="52.14.203.77"))
    strong = ai.correlate(ai.Facts(source_ip="52.14.203.77", session_count=4, source_ports=[4444],
                                   reverse_dns="ec2-52-14-203-77.compute-1.amazonaws.com",
                                   tls_fingerprint="ja3:abc", first_seen="2026-11-08T20:00:00Z"))
    order = ["insufficient_evidence", "low", "moderate", "elevated"]
    assert order.index(strong.confidence) > order.index(weak.confidence)


def test_the_report_states_what_is_missing():
    report = ai.correlate(ai.Facts(source_ip="52.14.203.77"))
    assert report.missing_information  # e.g. a second session, timestamps
    assert any("reuse" in m or "session" in m for m in report.missing_information)


def test_prohibited_actions_and_preservation_always_present():
    for facts in (ai.Facts(source_ip="52.14.203.77"), ai.Facts(source_ip="203.0.113.9")):
        report = ai.correlate(facts)
        assert len(report.prohibited_actions) >= 4
        assert any("access the provider account" in p for p in report.prohibited_actions)
        assert any("probe" in p for p in report.prohibited_actions)
        assert any("transcript" in p for p in report.evidence_preservation)


def test_the_digest_is_stable_and_content_addressed():
    a = ai.correlate(ai.Facts(source_ip="52.14.203.77", session_count=2, source_ports=[4444]))
    b = ai.correlate(ai.Facts(source_ip="52.14.203.77", session_count=2, source_ports=[4444]))
    c = ai.correlate(ai.Facts(source_ip="52.14.203.77", session_count=3, source_ports=[4444]))
    assert a.record_digest == b.record_digest != c.record_digest


def test_an_unparseable_address_yields_no_attribution():
    report = ai.correlate(ai.Facts(source_ip="not-an-address"))
    assert report.confidence == "insufficient_evidence"
    assert "no provider attribution" in report.hypothesis.statement


def test_the_correlator_cannot_make_a_connection():
    for module in ("aws_intel.py", "mirror.py"):
        tree = ast.parse((DEC / module).read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        assert names & {"socket", "urllib", "requests", "http", "subprocess", "os", "ssl"} == set(), module


def test_the_report_serialises_for_a_downstream_consumer():
    json.dumps(ai.correlate(ai.Facts(source_ip="52.14.203.77")).as_dict())


def test_cli_runs_both_tools():
    assert ai.main(["--json"]) == 0
    assert mx.main(["--json", "--sessions", "2"]) == 0


def test_both_modules_run_as_processes_not_just_as_functions():
    """Regression: aws_intel used sys.argv without importing sys, and calling main() in-process
    never touched the __main__ path. CI found it; this test now would."""
    import subprocess

    for script in ("mirror", "aws_intel"):
        result = subprocess.run([sys.executable, "-m", "harness.deception." + script, "--json"],
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, (script, result.stderr[-400:])
        assert json.loads(result.stdout)
