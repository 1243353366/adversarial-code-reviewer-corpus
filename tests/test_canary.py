"""Acceptance tests for the active canary, written against the failures the review named."""

from __future__ import annotations

import ast
from pathlib import Path

from harness.deception import canary as c
from harness.deception import mirror as mx


def _registry():
    return c.CanaryRegistry()


def test_identical_seeds_keep_distinct_canary_identities():
    """variation=False gives every session seed 1301; a token-keyed registry lost them."""
    mirror = mx.Mirror(variation=False)
    a = mirror.connect("198.51.100.41:41412")
    b = mirror.connect("198.51.100.42:41412")
    token_a = mirror.canaries.by_session[a.session_id].token
    token_b = mirror.canaries.by_session[b.session_id].token
    assert token_a != token_b
    assert len(mirror.canaries.by_session) == 2
    assert token_a in mirror.canaries.by_token and token_b in mirror.canaries.by_token


def test_a_read_in_one_session_cannot_fire_another_sessions_canary():
    mirror = mx.Mirror(variation=False)
    a = mirror.connect("198.51.100.51:41412")
    b = mirror.connect("198.51.100.52:41412")
    a.send("cat /var/www/app/.env\n")
    assert len(mirror.canaries.by_session[a.session_id].touches) == 1
    assert mirror.canaries.by_session[b.session_id].touches == []


def test_a_real_cat_through_the_mirror_fires_the_right_canary():
    mirror = mx.Mirror()
    a = mirror.connect("198.51.100.61:41412")
    a.send("cat /home/deploy/.aws/credentials\n")        # no registry call in the test
    touches = mirror.canaries.by_session[a.session_id].touches
    assert len(touches) == 1
    assert touches[0]["where"] == "file_read"


def test_planting_preserves_existing_synthetic_content():
    registry = _registry()
    files = {"/var/www/app/.env": "APP_ENV=production\nDB_HOST=127.0.0.1\n"}
    registry.plant("mx-a", 7, files)
    body = files["/var/www/app/.env"]
    assert body.startswith("APP_ENV=production\nDB_HOST=127.0.0.1\n")
    assert registry.by_session["mx-a"].token in body


def test_a_quiet_session_produces_no_alerts():
    mirror = mx.Mirror()
    quiet = mirror.connect("198.51.100.71:41412")
    for command in ("whoami\n", "uname -a\n", "ps\n", "ls /var/www/app\n"):
        quiet.send(command)
    assert mirror.canaries.by_session[quiet.session_id].touches == []
    assert mirror.canaries.report()["priority_high"] == []


def test_reuse_links_sessions_without_claiming_identity():
    registry = _registry()
    registry.plant("mx-alpha", 1301, {})
    registry.plant("mx-beta", 1301, {})
    token = registry.by_session["mx-alpha"].token
    registry.observe("mx-beta", f"export AWS_ACCESS_KEY_ID={token}")
    links = registry.links()
    assert len(links) == 1
    assert links[0]["sessions"] == ["mx-alpha", "mx-beta"]
    assert links[0]["identity_claim"] == "not established"
    assert "not people" in links[0]["note"]


def test_deterministic_tokens_are_labelled_predictable():
    canary = c.Canary("mx-a", 1301)
    assert canary.secret_backed is False
    assert canary.record()["predictable"] is True
    assert c.derive_token(1301, "mx-a") == canary.token      # reproducible, by design


def test_secret_keyed_tokens_differ_and_are_not_labelled_predictable():
    plain = c.Canary("mx-a", 1301)
    keyed = c.Canary("mx-a", 1301, secret=b"not-in-this-repository")
    assert keyed.token != plain.token
    assert keyed.secret_backed is True
    assert keyed.record()["predictable"] is False


def test_the_canary_cannot_leave_the_machine():
    source = Path(c.__file__).read_text()
    tree = ast.parse(source)
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names} | {n.module.split(".")[0] for n in ast.walk(tree)
                                      if isinstance(n, ast.ImportFrom) and n.module}
    assert imported <= {"__future__", "hashlib", "hmac", "ast", "pathlib"}
    for beacon in ("urlopen", "socket", "connect(", "sendto", "requests"):
        assert beacon not in source


def test_the_demo_runs_as_a_process():
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-m", "harness.deception.canary"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr[-300:]
    assert "identity: not established" in result.stdout
    assert "unguessability" in result.stdout
