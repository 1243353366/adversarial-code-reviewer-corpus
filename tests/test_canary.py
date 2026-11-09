"""The active canary: it must act, and it must not reach out.

The boundary tests here are the point. A canary that beacons is not a stronger canary; it is a
different kind of system, and these tests exist so that change cannot happen quietly.
"""
from __future__ import annotations

import ast
from pathlib import Path

from harness.deception import canary as cn

MODULE = Path(cn.__file__)


def _env():
    class _E:
        files: dict[str, str] = {}
    return _E()


def test_a_token_is_deterministic_per_seed_and_differs_across_seeds():
    assert cn.derive_token(1301) == cn.derive_token(1301)
    assert cn.derive_token(1301) != cn.derive_token(1302)
    assert cn.derive_token(1301).startswith("AKIA")


def test_planting_writes_the_token_into_files_the_session_serves():
    env = _env()
    registry = cn.CanaryRegistry()
    planted = registry.plant("mx-a", 7, env)
    assert planted.planted_at
    assert planted.token in env.files["/var/www/app/.env"]


def test_reading_the_planted_file_is_the_alarm():
    registry = cn.CanaryRegistry()
    planted = registry.plant("mx-a", 7, _env())
    hit = registry.observe_file_read("mx-a", "/var/www/app/.env")
    assert hit is not None and hit.where == "file_read"
    assert planted.priority == "high"


def test_a_quiet_session_leaves_the_canary_untouched():
    registry = cn.CanaryRegistry()
    registry.plant("mx-a", 7, _env())
    assert registry.observe("mx-a", "ls /var/www") is None
    assert registry.report()["tokens_touched"] == 0


def test_reuse_in_another_session_links_the_two_attempts():
    registry = cn.CanaryRegistry()
    planted = registry.plant("mx-a", 7, _env())
    registry.observe("mx-b", f"export AWS_ACCESS_KEY_ID={planted.token}")
    links = registry.links()
    assert links == [{"planted_in": "mx-a", "also_seen_in": "mx-b",
                      "token_suffix": planted.token[-6:]}]


def test_the_report_never_carries_the_whole_token():
    registry = cn.CanaryRegistry()
    planted = registry.plant("mx-a", 7, _env())
    registry.observe("mx-b", f"k={planted.token}")
    text = str(registry.report())
    assert planted.token not in text
    assert planted.token[-6:] in text


def test_priority_rises_only_when_the_token_is_used():
    registry = cn.CanaryRegistry()
    registry.plant("mx-a", 7, _env())
    assert registry.report()["priority"] == "normal"
    registry.observe_file_read("mx-a", "/home/deploy/.aws/credentials")
    assert registry.report()["priority"] == "high"


def test_the_canary_has_no_route_off_the_machine():
    """No socket, no urllib, no subprocess, no callback of any kind."""
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= {"__future__", "hashlib", "dataclasses"}, imported


def test_there_is_no_beacon_function_to_call():
    """The absence is the design: an intel file cannot be pointed at a target."""
    source = MODULE.read_text()
    for forbidden in ("requests.", "urlopen", "socket.", "subprocess.", "connect(",
                      "sendto", "exfil"):
        assert forbidden not in source, forbidden
