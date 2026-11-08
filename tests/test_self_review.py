"""The self-review script gets the treatment it asks for: a test per rule, both ways.

A linter that only ever fires is as useless as one that never does, so each rule is tested
for the finding it should raise and for the clean code it should leave alone.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import self_review as SR  # noqa: E402


def run(rule, code: str, path: str = "harness/x.py"):
    return rule(ast.parse(code), path)


def test_peer_role_from_payload_is_flagged():
    code = 'def f(msg):\n    if msg["role"] == "operator":\n        return True\n'
    assert run(SR.rule_peer_authority, code)
    code = 'def f(msg):\n    if msg.get("origin") == "internal":\n        return True\n'
    assert run(SR.rule_peer_authority, code)


def test_reading_peer_fields_for_other_purposes_is_not_flagged():
    code = 'def f(msg):\n    return msg.get("id")\n'
    assert run(SR.rule_peer_authority, code) == []


def test_wire_length_used_as_a_size_is_flagged():
    code = ("import struct\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    return peer.read_exact(n)\n")
    assert run(SR.rule_length_before_bound, code)


def test_wire_length_bounded_before_use_is_not_flagged():
    code = ("import struct\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    return peer.read_exact(min(n, 1024))\n")
    assert run(SR.rule_length_before_bound, code) == []


def test_queue_without_maxlen_is_flagged():
    code = "from collections import deque\nq = deque()\n"
    assert run(SR.rule_deque_without_maxlen, code)
    assert run(SR.rule_deque_without_maxlen, "from collections import deque\nq = deque(maxlen=4)\n") == []


def test_mutable_default_is_flagged():
    assert run(SR.rule_mutable_default, "def f(x=[]):\n    return x\n")


def test_bare_except_is_flagged():
    code = "def f():\n    try:\n        pass\n    except:\n        pass\n"
    assert run(SR.rule_bare_except, code)


def test_origin_compared_to_a_literal_is_flagged():
    code = 'def f(origin):\n    return origin == "internal"\n'
    assert run(SR.rule_string_identity, code)
    code = 'def f(env):\n    return env.cap is CAP\n'
    assert run(SR.rule_string_identity, code) == []


def test_unfloored_ratio_is_flagged_and_a_floored_one_is_not():
    flagged = "def f(a, b):\n    return a / b\n"
    assert run(SR.rule_ratio_without_floor, flagged)
    floored = "def f(a, b):\n    d = max(b, 1)\n    return a / d\n"
    assert run(SR.rule_ratio_without_floor, floored) == []


def test_ratio_rule_ignores_authoring_scripts():
    code = "def f(a, b):\n    return a / b\n"
    assert run(SR.rule_ratio_without_floor, code, path="tools/report.py") == []


def test_threshold_constants_outside_policy_are_reported_as_low():
    findings = run(SR.rule_policy_scatter, "MAX_HOPS = 1\nSEED = 7\n")
    assert [f.rule for f in findings] == ["policy_scatter"]
    assert findings[0].severity == SR.LOW


def test_allowlist_entry_without_a_reason_refuses_to_load(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("harness/a.py:bare_except  # ok\n")
    with pytest.raises(SystemExit):
        SR.load_allowlist(path)


def test_allowlist_entry_with_a_reason_loads(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("harness/a.py:bare_except  # fixture that must remain broken on purpose\n")
    assert ("harness/a.py", "bare_except") in SR.load_allowlist(path)


def test_repository_reviews_clean_of_high_findings():
    """The point of pointing this at ourselves: zero high findings, and no suppression blanket."""
    findings = SR.review()
    assert [f.render() for f in findings if f.severity == SR.HIGH] == []
    assert len(SR.load_allowlist()) <= 5
