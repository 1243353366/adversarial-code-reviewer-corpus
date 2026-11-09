"""The self-review script gets the treatment it asks for: a test per rule, both ways.

A linter that only ever fires is as useless as one that never does, so each rule is tested
for the finding it should raise and for the clean code it should leave alone. The exemption
mechanism gets the harder tests, because a suppression system that is broader than its
written reason is the defect this repository keeps documenting.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

import self_review as SR  # noqa: E402


def run(rule, code: str, path: str = "harness/x.py"):
    return rule(ast.parse(code), path)


def fp_of(code: str) -> str:
    return SR.fingerprint_of(code)


# --- rules -------------------------------------------------------------------------

def test_peer_role_from_payload_is_flagged():
    assert run(SR.rule_peer_authority, 'def f(msg):\n    return msg["role"]\n')
    assert run(SR.rule_peer_authority, 'def f(msg):\n    return msg.get("origin")\n')


def test_reading_peer_fields_for_other_purposes_is_not_flagged():
    assert run(SR.rule_peer_authority, 'def f(msg):\n    return msg.get("id")\n') == []


def test_wire_length_used_as_a_size_is_flagged():
    code = ("import struct\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    return peer.read_exact(n)\n")
    assert run(SR.rule_length_before_bound, code)


def test_wire_length_through_a_conversion_alias_is_flagged():
    """R61: int() around the length does not bound it."""
    code = ("import struct\n"
            "def f(peer):\n"
            "    (declared,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    size = int(declared)\n"
            "    return peer.read_exact(size)\n")
    assert run(SR.rule_length_before_bound, code)


def test_wire_length_through_arithmetic_is_flagged():
    code = ("import struct\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    want = n * 4\n"
            "    return peer.read_exact(want)\n")
    assert run(SR.rule_length_before_bound, code)


def test_wire_length_clamped_or_checked_is_not_flagged():
    clamped = ("import struct\n"
               "def f(peer):\n"
               "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
               "    return peer.read_exact(min(n, 1024))\n")
    assert run(SR.rule_length_before_bound, clamped) == []
    checked = ("import struct\n"
               "MAX_FRAME = 1024\n"
               "def f(peer):\n"
               "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
               "    if n > MAX_FRAME:\n"
               "        raise ValueError('too long')\n"
               "    return peer.read_exact(n)\n")
    assert run(SR.rule_length_before_bound, checked) == []


def test_max_is_not_a_ceiling_for_a_wire_length():
    """R63: max() sets a floor, so an attacker can still choose an enormous length."""
    code = ("import struct\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    size = max(n, 1)\n"
            "    return peer.read_exact(size)\n")
    assert run(SR.rule_length_before_bound, code)


def test_min_against_something_that_is_not_a_limit_does_not_bound():
    code = ("import struct\n"
            "def f(peer, other):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    size = min(n, other)\n"
            "    return peer.read_exact(size)\n")
    assert run(SR.rule_length_before_bound, code)


def test_a_comparison_that_does_not_reject_is_not_a_bound():
    """R64: the comparison is present, but nothing refuses the unsafe value."""
    code = ("import struct\n"
            "MAX_FRAME = 1024\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    if n < MAX_FRAME:\n"
            "        pass\n"
            "    return peer.read_exact(n)\n")
    assert run(SR.rule_length_before_bound, code)


def test_a_rejecting_guard_still_counts_as_a_bound():
    code = ("import struct\n"
            "MAX_FRAME = 1024\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    if n > MAX_FRAME:\n"
            "        raise ValueError('too long')\n"
            "    return peer.read_exact(n)\n")
    assert run(SR.rule_length_before_bound, code) == []


CHAIN = ("import struct\n"
         "def f(peer):\n"
         "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
         "    a = n\n"
         "    b = a\n"
         "    c = b\n"
         "    d = c\n"
         "    size = int(d)\n"
         "    return peer.read_exact(size)\n")


def test_taint_follows_a_long_alias_chain():
    """Propagation runs to a fixpoint, so chain length is not a blind spot by construction."""
    assert run(SR.rule_length_before_bound, CHAIN)


def test_constant_size_is_not_flagged():
    code = "def f(peer):\n    return peer.read_exact(4)\n"
    assert run(SR.rule_length_before_bound, code) == []


def test_queue_without_maxlen_is_flagged():
    assert run(SR.rule_deque_without_maxlen, "from collections import deque\nq = deque()\n")
    assert run(SR.rule_deque_without_maxlen, "from collections import deque\nq = deque(maxlen=4)\n") == []


def test_mutable_default_is_flagged():
    assert run(SR.rule_mutable_default, "def f(x=[]):\n    return x\n")


def test_bare_except_is_flagged():
    assert run(SR.rule_bare_except, "def f():\n    try:\n        pass\n    except:\n        pass\n")


def test_origin_compared_to_a_literal_is_flagged():
    assert run(SR.rule_string_identity, 'def f(origin):\n    return origin == "internal"\n')
    assert run(SR.rule_string_identity, "def f(env):\n    return env.cap is CAP\n") == []


def test_unfloored_ratio_is_flagged_and_a_floored_one_is_not():
    assert run(SR.rule_ratio_without_floor, "def f(a, b):\n    return a / b\n")
    assert run(SR.rule_ratio_without_floor, "def f(a, b):\n    d = max(b, 1)\n    return a / d\n") == []


def test_a_floor_in_one_function_does_not_protect_another():
    """R60: the reviewer's example, which the module-wide version got wrong."""
    code = ("def safe(numerator, request_size):\n"
            "    denominator = max(request_size, 1)\n"
            "    return numerator / denominator\n"
            "\n"
            "def unsafe(numerator, denominator):\n"
            "    return numerator / denominator\n")
    findings = run(SR.rule_ratio_without_floor, code)
    assert len(findings) == 1
    assert findings[0].line == 6


def test_ratio_rule_ignores_authoring_scripts():
    assert run(SR.rule_ratio_without_floor, "def f(a, b):\n    return a / b\n", path="tools/report.py") == []


def test_threshold_constants_outside_policy_are_reported_as_low():
    findings = run(SR.rule_policy_scatter, "MAX_HOPS = 1\nSEED = 7\n")
    assert [f.rule for f in findings] == ["policy_scatter"]
    assert findings[0].severity == SR.LOW


# --- exemptions --------------------------------------------------------------------

TWO_OCCURRENCES = ("import struct\n"
                   "def f(peer):\n"
                   "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
                   "    return peer.read_exact(n)\n"
                   "def g(peer):\n"
                   "    (m,) = struct.unpack('>I', peer.read_exact(4))\n"
                   "    return peer.read_exact(m)\n")


def test_an_exemption_covers_one_occurrence_not_the_whole_file():
    """R59: exempting one occurrence must leave the other reported."""
    code = TWO_OCCURRENCES
    line = code.splitlines()[3]
    allowed = {("harness/x.py", "peer_length_before_bound", fp_of(line)): "fixture, one of two"}
    kept = SR.apply_allowlist(_findings_for(code), allowed)
    assert len(kept) == 1
    assert kept[0].line == 7  # the occurrence at line 4 was exempted, line 7 was not


def test_identical_lines_make_an_exemption_ambiguous_and_that_is_an_error():
    code = ("import struct\n"
            "def f(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    return peer.read_exact(n)\n"
            "def g(peer):\n"
            "    (n,) = struct.unpack('>I', peer.read_exact(4))\n"
            "    return peer.read_exact(n)\n")
    same = code.splitlines()[3]
    allowed = {("harness/x.py", "peer_length_before_bound", fp_of(same)): "both look the same"}
    with pytest.raises(SystemExit):
        SR.apply_allowlist(_findings_for(code), allowed)


def test_a_stale_exemption_fails_the_run():
    allowed = {("harness/x.py", "peer_length_before_bound", "deadbeef"): "no longer matches anything"}
    with pytest.raises(SystemExit):
        SR.apply_allowlist(_findings_for("def f(peer):\n    return peer.read_exact(4)\n"), allowed)


def _findings_for(code: str) -> list[SR.Finding]:
    tree = ast.parse(code)
    lines = code.splitlines()
    out = []
    for rule in SR.RULES:
        for f in rule(tree, "harness/x.py"):
            out.append(SR.Finding(f.path, f.line, f.rule, f.severity, f.why,
                                  SR.fingerprint_of(lines[f.line - 1])))
    return out


def test_allowlist_requires_a_reason(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("harness/a.py:bare_except:deadbeef  # ok\n")
    with pytest.raises(SystemExit):
        SR.load_allowlist(path)


def test_allowlist_requires_a_fingerprint(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("harness/a.py:bare_except  # a reason long enough to satisfy the loader\n")
    with pytest.raises(SystemExit):
        SR.load_allowlist(path)


def test_allowlist_rejects_an_unknown_rule(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("harness/a.py:no_such_rule:deadbeef  # a reason long enough to satisfy\n")
    with pytest.raises(SystemExit):
        SR.load_allowlist(path)


def test_allowlist_rejects_a_nonexistent_target(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("harness/nope.py:bare_except:deadbeef  # a reason long enough to satisfy\n")
    with pytest.raises(SystemExit):
        SR.load_allowlist(path)


def test_allowlist_rejects_duplicates(tmp_path):
    path = tmp_path / "allow.txt"
    entry = "harness/a.py:bare_except:deadbeef  # a reason long enough to satisfy the loader\n"
    path.write_text(entry + entry)
    with pytest.raises(SystemExit):
        SR.load_allowlist(path)


def test_the_committed_allowlist_is_exactly_what_is_expected():
    """Exact contents, not a count, so an added suppression has to be argued for here too."""
    allowed = SR.load_allowlist()
    assert sorted((p, r) for p, r, _ in allowed) == [
        ("harness/provenance/listener.py", "peer_authority_from_payload"),
        ("harness/provenance/listener.py", "peer_authority_from_payload"),
        ("harness/untrusted_peer/alias_chain.py", "peer_length_before_bound"),
        ("harness/untrusted_peer/naive.py", "peer_authority_from_payload"),
        ("harness/untrusted_peer/naive.py", "peer_length_before_bound"),
    ]
    # the two listener entries must be different occurrences, which is the point
    listener_fps = {fp for (p, r, fp) in allowed if p == "harness/provenance/listener.py"}
    assert len(listener_fps) == 2


def test_every_rule_name_used_in_allowlists_is_a_real_rule():
    assert {f.rule for f in SR._collect()} <= SR.RULE_NAMES


def test_repository_reviews_clean_of_high_findings():
    findings = SR.review()
    assert [f.render() for f in findings if f.severity == SR.HIGH] == []
