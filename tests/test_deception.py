"""What the deception layer guarantees, and where each guarantee ends.

Every test here pairs a naive implementation or an adversary's cleanup step against the
shipped one, so a passing suite means the difference was measured, not asserted.
"""
from __future__ import annotations

import os

import pytest

from harness.deception import Issuance, watermark
from harness.deception.alerts import CanaryLedger
from harness.deception.credentials import CredentialRegistry
from harness.deception.shell import SimulatedShell
from harness.deception.vault import EscapedRoot, FakeTree


def build(campaign="camp-alpha", issuance_id="IS-0001"):
    issuance = Issuance.create(campaign, issuance_id)
    registry = CredentialRegistry()
    tree = FakeTree(issuance)
    shell = SimulatedShell(issuance, registry, tree)
    ledger = CanaryLedger(registry)
    ledger.issue(issuance)
    return issuance, registry, tree, shell, ledger


def naive_read(tree: FakeTree, path: str) -> str:
    """The defect: normalize first, then look up whatever is left."""
    import posixpath
    norm = posixpath.normpath("/" + path.lstrip("/"))
    table = {"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"}
    table.update(tree.files)
    return table[norm]


def test_traversal_serves_a_host_path_when_normalized_first():
    _, _, tree, _, _ = build()
    assert "root:x:0:0" in naive_read(tree, "/../../etc/passwd")
    with pytest.raises(EscapedRoot):
        tree.read("/../../etc/passwd")
    assert tree.access_log[-1]["event"] == "escape"


def test_environment_output_cannot_carry_the_listeners_environment(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "REAL-DEPLOYMENT-SECRET")
    monkeypatch.setenv("HOME", "/root")
    _, registry, _, shell, _ = build()
    out = shell.run("env")["stdout"]
    assert "REAL-DEPLOYMENT-SECRET" not in out
    assert "/root" not in out
    # everything that looks like a credential is one the registry issued
    for line in out.splitlines():
        if not any(k in line for k in ("AWS", "PASSWORD", "TOKEN")):
            continue
        key, value = line.split("=", 1)
        if key == "DEPLOY_TOKEN":
            # a fingerprint, not a credential the registry issues
            assert value.startswith(registry.__class__.__name__[:0]) and all(c in "0123456789abcdef" for c in value[:24])
        else:
            assert registry.known(value), (key, value)


def test_credentials_are_generated_from_the_issuance_not_copied():
    a, ra, *_ = build(issuance_id="IS-0100")
    b, rb, *_ = build(issuance_id="IS-0101")
    assert ra.aws_like(a) == CredentialRegistry().aws_like(Issuance.create("camp-alpha", "IS-0100"))
    assert ra.aws_like(a) != rb.aws_like(b)
    # nothing issued exists in the process environment
    env_values = set(os.environ.values())
    for value in (ra.aws_like(a), ra.secret_key(a), ra.db_password(a)):
        assert value not in env_values
    assert rb.attribute(rb.aws_like(b)).issuance_id == "IS-0101"
    assert ra.attribute(rb.aws_like(b)) is None  # a different registry knows nothing about it


def test_watermark_survives_strip_and_reformat():
    issuance, _, tree, _, _ = build()
    body = tree.read("/srv/app/README.internal.md")
    canonical = issuance.fingerprint("mark", 8)
    assert watermark.attribute(body.strip()) == [canonical]
    assert watermark.attribute(body.replace("\n", "\r\n")) == [canonical]
    assert watermark.attribute(body.replace(" ", "  ")) == [canonical]


def test_watermark_survives_zero_width_stripping_on_the_visible_layer():
    issuance, _, tree, _, _ = build()
    body = tree.read("/srv/app/README.internal.md")
    scrubbed = body.replace("\u200b", "").replace("\u200c", "")
    assert watermark.attribute(scrubbed) == [issuance.fingerprint("mark", 8)]


def test_both_layers_removed_is_honestly_unattributable():
    _, _, tree, _, _ = build()
    body = tree.read("/srv/app/README.internal.md")
    stripped = body.replace("\u200b", "").replace("\u200c", "")
    stripped = [ln for ln in stripped.splitlines() if "[ref:" not in ln]
    assert watermark.attribute("\n".join(stripped)) == []


def test_two_leaks_in_one_document_report_two_issuances():
    first, _, tree, _, _ = build(issuance_id="IS-0200")
    second = Issuance.create("camp-alpha", "IS-0201")
    merged = tree.read("/srv/app/README.internal.md") + watermark.apply("second source", second)
    assert watermark.attribute(merged) == [first.fingerprint("mark", 8), second.fingerprint("mark", 8)]


def test_canary_fires_once_per_issuance_on_reuse():
    _, _, _, shell, ledger = build()
    transcript = shell.run("env")["stdout"]
    first = ledger.scan(transcript)
    second = ledger.scan(transcript)
    assert first and not second
    assert {a.issuance_id for a in first} == {"IS-0001"}
    assert all(a.campaign == "camp-alpha" for a in first)


def test_unknown_command_fails_plausibly_and_executes_nothing():
    _, _, _, shell, _ = build()
    result = shell.run("rm -rf / --no-preserve-root")
    assert result["exit"] == 127
    assert "not found" in result["stderr"]
    assert result["stdout"] == ""


def test_package_contains_no_execution_primitives():
    """Prose may name `subprocess`; the code may not import or call it."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "harness" / "deception"
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name.split(".")[0] not in ("subprocess", "pty") for a in node.names), path.name
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in ("subprocess", "pty"), path.name
            elif isinstance(node, ast.Call):
                fn = node.func
                name = getattr(fn, "id", None) or getattr(fn, "attr", None)
                assert name not in ("eval", "exec", "system", "popen", "spawn"), f"{path.name}: {name}"


def test_silent_issuances_are_named_not_hidden():
    _, _, _, shell, ledger = build()
    quiet = Issuance.create("camp-alpha", "IS-0300")
    ledger.issue(quiet)
    ledger.scan(shell.run("env")["stdout"])
    assert "IS-0001" not in ledger.summary()["silent"]
    assert "IS-0300" in ledger.summary()["silent"]
