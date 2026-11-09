#!/usr/bin/env python3
"""Drift detection against a mutable baseline, and honest about which one it is.

What this establishes: the working tree matches a reviewed inventory, and the inventory's own
digest matches the anchor recorded in SECURITY.md. Both live in the repository being checked,
so a party who controls the repository can regenerate both. That is why CI also accepts an
anchor from outside the checkout (``--anchor``, ``--verifier-digest``, normally repository
variables) and why this file is stdlib-only: it has to run before anything is installed.

What this does not establish: that the verifier itself, or the runner, is trustworthy. A
replaced ``tools/integrity.py`` runs before it can be checked. The workflow pins the verifier's
digest in a variable outside the checkout so a replacement has to be an edit to CI settings as
well, which is a cost, not a proof. Signed commits and an external anchor service are the real
answer and are not implemented here.

Standard library only, by rule. tests/test_integrity.py asserts that by parsing this file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
LOCK = Path("harness") / "integrity.lock"
ANCHOR_DOC = Path("SECURITY.md")

CANONICAL_HOST = "github.com"
CANONICAL_PATH = "1243353366/assay"

COVERED = ("harness", "tools", "tests", "pyproject.toml", "requirements-dev.txt", ".github/workflows")
# The lock cannot hash itself; a test asserts this explicitly rather than leaving it implied.
EXCLUDED_SUFFIXES = (".lock",)


def digest_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for entry in COVERED:
        target = root / entry
        if target.is_file():
            files[entry] = digest_of(target)
            continue
        if not target.is_dir():
            continue
        for path in sorted(target.rglob("*")):
            if not path.is_file() or path.suffix in EXCLUDED_SUFFIXES:
                continue
            if "__pycache__" in path.parts:
                continue
            files[path.relative_to(root).as_posix()] = digest_of(path)
    return dict(sorted(files.items()))


def set_digest(files: dict[str, str]) -> str:
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def build(root: Path = ROOT) -> dict:
    files = collect(root)
    return {"algorithm": "sha256", "files": files, "set_digest": set_digest(files)}


def read_lock(root: Path = ROOT) -> dict:
    path = root / LOCK
    return json.loads(path.read_text())


def read_anchor(root: Path = ROOT) -> tuple[str, int]:
    """The digest and file count pinned in SECURITY.md, which is not in the covered set."""
    text = (root / ANCHOR_DOC).read_text()
    digest = re.search(r"set digest:\s*([0-9a-f]{64})", text)
    count = re.search(r"files:\s*(\d+)", text)
    if not digest or not count:
        raise ValueError("SECURITY.md has no parseable 'set digest:' / 'files:' anchor")
    return digest.group(1), int(count.group(1))


def verify(root: Path = ROOT, anchor: str | None = None) -> list[str]:
    problems: list[str] = []
    try:
        lock = read_lock(root)
    except (OSError, ValueError) as exc:
        return [f"lock unreadable: {exc}"]

    current = collect(root)
    recorded = lock.get("files", {})
    for name in sorted(set(recorded) - set(current)):
        problems.append(f"missing: {name}")
    for name in sorted(set(current) - set(recorded)):
        problems.append(f"added: {name} (a new file only has to be importable)")
    for name in sorted(set(current) & set(recorded)):
        if current[name] != recorded[name]:
            problems.append(f"modified: {name}")

    computed = set_digest(current)
    if lock.get("set_digest") != computed:
        problems.append(f"lock set digest {lock.get('set_digest', '?')[:12]} != computed {computed[:12]}")

    try:
        pinned, count = read_anchor(root)
    except (OSError, ValueError) as exc:
        problems.append(f"anchor unenforced: {exc}")
    else:
        if pinned != computed:
            problems.append(f"SECURITY.md anchor {pinned[:12]} != computed {computed[:12]}")
        if count != len(current):
            problems.append(f"SECURITY.md count {count} != {len(current)} files")

    if anchor and anchor != computed:
        problems.append(f"external anchor {anchor[:12]} != computed {computed[:12]}")
    return problems


def parse_remote(url: str) -> tuple[str, str]:
    """Normalise https, ssh:// and scp-style remotes to (host, owner/repo)."""
    url = url.strip()
    scp = re.match(r"^(?:[^@/]+@)?([^:/]+):(?!//)(.+)$", url)
    if scp and "://" not in url:
        host, path = scp.group(1), scp.group(2)
    else:
        parts = urlsplit(url)
        host, path = parts.hostname or "", parts.path
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return host.lower(), path


def identity(root: Path = ROOT, require_branch: str | None = None) -> list[str]:
    def git(*args: str) -> str:
        out = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
        return out.stdout.strip()

    problems: list[str] = []
    raw = git("config", "--get", "remote.origin.url")
    host, path = parse_remote(raw)
    if (host, path) != (CANONICAL_HOST, CANONICAL_PATH):
        problems.append(f"origin is {host}/{path}, not {CANONICAL_HOST}/{CANONICAL_PATH}")

    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if require_branch and branch != require_branch:
        problems.append(f"branch is {branch!r}, not {require_branch!r}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="drift detection for this repository")
    parser.add_argument("action", choices=["build", "verify", "digest", "identity", "all"])
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--anchor", default=os.environ.get("ASSAY_ANCHOR", ""))
    parser.add_argument("--verifier-digest", default=os.environ.get("ASSAY_VERIFIER_DIGEST", ""))
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    if args.action == "build":
        data = build(root)
        (root / LOCK).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(f"wrote {LOCK}: {len(data['files'])} files")
        print(f"set digest {data['set_digest']}")
        return 0

    if args.action == "digest":
        print(build(root)["set_digest"])
        return 0

    problems: list[str] = []
    if args.verifier_digest:
        actual = digest_of(root / "tools" / "integrity.py")
        if actual != args.verifier_digest:
            problems.append(f"verifier digest {actual[:12]} != pinned {args.verifier_digest[:12]}")
    if args.action in ("verify", "all"):
        problems += verify(root, anchor=args.anchor or None)
    if args.action in ("identity", "all"):
        problems += identity(root)

    for line in problems:
        print(f"  {line}")
    if problems:
        print(f"integrity FAILED: {len(problems)} problem(s)")
        return 1

    data = collect(root)
    anchored = "external anchor checked" if args.anchor else "no external anchor supplied (SECURITY.md only)"
    print(f"integrity ok: {len(data)} files match the reviewed set ({set_digest(data)[:16]}), {anchored}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
