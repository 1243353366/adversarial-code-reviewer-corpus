"""The verifier's own trust boundary, tested by tampering.

Each test breaks one thing on purpose. A checker that passes when its inputs are wrong is
decoration, and this file exists so that claim is checkable rather than asserted.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from tools import integrity as I

ROOT = Path(__file__).resolve().parents[1]


def make_tree(tmp_path: Path) -> Path:
    (tmp_path / "tools").mkdir()
    (tmp_path / "testreq.txt").write_text("pytest\n")
    (tmp_path / "tools" / "a.py").write_text("x = 1\n")
    (tmp_path / "SECURITY.md").write_text("    set digest: " + "0" * 64 + "\n    files:      2\n")
    return tmp_path


def build_and_pin(root: Path) -> dict:
    data = I.build(root)
    (root / "harness").mkdir(exist_ok=True)
    (root / I.LOCK).write_text(json.dumps(data, indent=2, sort_keys=True))
    doc = f"    set digest: {data['set_digest']}\n    files:      {len(data['files'])}\n"
    (root / "SECURITY.md").write_text(doc)
    return data


def test_the_lock_cannot_hash_itself(tmp_path):
    """The invariant behind excluding .lock, asserted rather than implied."""
    root = make_tree(tmp_path)
    (root / "harness").mkdir()
    (root / I.LOCK).write_text("{}")
    files = I.collect(root)
    assert not any(name.endswith(".lock") for name in files)


def test_a_clean_tree_verifies(tmp_path):
    root = make_tree(tmp_path)
    build_and_pin(root)
    assert I.verify(root) == []


def test_added_file_is_named(tmp_path):
    root = make_tree(tmp_path)
    build_and_pin(root)
    (root / "tools" / "evil.py").write_text("import os\n")
    assert any("added" in p and "evil.py" in p for p in I.verify(root))


def test_modified_file_is_named(tmp_path):
    root = make_tree(tmp_path)
    build_and_pin(root)
    (root / "tools" / "a.py").write_text("x = 2\n")
    assert any("modified" in p and "a.py" in p for p in I.verify(root))


def test_removed_file_is_named(tmp_path):
    root = make_tree(tmp_path)
    build_and_pin(root)
    (root / "tools" / "a.py").unlink()
    assert any("missing" in p for p in I.verify(root))


def test_a_tampered_lock_digest_fails(tmp_path):
    """Rewriting the lock to match a tampered tree must still fail on the SECURITY anchor."""
    root = make_tree(tmp_path)
    build_and_pin(root)
    (root / "tools" / "a.py").write_text("x = 2\n")
    data = I.build(root)
    (root / I.LOCK).write_text(json.dumps(data, indent=2, sort_keys=True))
    problems = I.verify(root)
    assert any("SECURITY.md anchor" in p for p in problems)


def test_a_tampered_anchor_fails(tmp_path):
    root = make_tree(tmp_path)
    data = build_and_pin(root)
    (root / "SECURITY.md").write_text(f"    set digest: {'a' * 64}\n    files:      {len(data['files'])}\n")
    assert any("SECURITY.md anchor" in p for p in I.verify(root))


def test_an_anchor_count_mismatch_fails(tmp_path):
    root = make_tree(tmp_path)
    data = build_and_pin(root)
    (root / "SECURITY.md").write_text(f"    set digest: {data['set_digest']}\n    files:      99\n")
    assert any("count" in p for p in I.verify(root))


def test_an_external_anchor_that_disagrees_fails(tmp_path):
    root = make_tree(tmp_path)
    build_and_pin(root)
    assert I.verify(root, anchor="b" * 64)
    assert any("external anchor" in p for p in I.verify(root, anchor="b" * 64))


def test_an_external_anchor_that_agrees_passes(tmp_path):
    root = make_tree(tmp_path)
    data = build_and_pin(root)
    assert I.verify(root, anchor=data["set_digest"]) == []


def test_a_dependency_manifest_change_is_a_finding(tmp_path):
    """requirements-dev.txt is covered, which is why CI verifies before installing it."""
    root = tmp_path
    (root / "requirements-dev.txt").write_text("pytest\n")
    (root / "SECURITY.md").write_text(f"    set digest: {'0' * 64}\n    files:      1\n")
    data = I.build(root)
    (root / I.LOCK.parent).mkdir(exist_ok=True)
    (root / I.LOCK).write_text(json.dumps(data, indent=2, sort_keys=True))
    (root / "SECURITY.md").write_text(f"    set digest: {data['set_digest']}\n    files:      {len(data['files'])}\n")
    assert I.verify(root) == []
    (root / "requirements-dev.txt").write_text("pytest\npytest-cov\n")
    assert any("requirements-dev.txt" in p for p in I.verify(root))


@pytest.mark.parametrize("url,want", [
    ("https://github.com/1243353366/assay.git", ("github.com", "1243353366/assay")),
    ("https://x-access-token:abc@github.com/1243353366/assay.git", ("github.com", "1243353366/assay")),
    ("git@github.com:1243353366/assay.git", ("github.com", "1243353366/assay")),
    ("ssh://git@github.com/1243353366/assay", ("github.com", "1243353366/assay")),
    ("https://github.com/1243353366/assay-mirror.git", ("github.com", "1243353366/assay-mirror")),
    ("https://github.com/1243353366/assay/tree/evil", ("github.com", "1243353366/assay/tree/evil")),
])
def test_remote_parsing_is_exact_not_substring(url, want):
    assert I.parse_remote(url) == want


def test_the_verifier_is_standard_library_only():
    """It runs before pip install, so a third-party import would be a bootstrap failure."""
    tree = ast.parse((ROOT / "tools" / "integrity.py").read_text())
    allowed = {"argparse", "hashlib", "json", "os", "re", "subprocess", "sys", "pathlib", "urllib", "__future__"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed, imported - allowed


def test_the_harness_has_no_path_bootstrap():
    """sys.path manipulation was the shadowing vector; the package handles resolution now."""
    offenders = []
    for path in (ROOT / "harness").rglob("*.py"):
        if "sys.path" in path.read_text():
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_the_repository_itself_verifies():
    assert I.verify(ROOT) == []
