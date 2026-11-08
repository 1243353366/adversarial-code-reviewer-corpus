#!/usr/bin/env python3
"""Branch protection: recorded expectations, and the live comparison they stand in for.

    python tools/check_protection.py            # recorded snapshot (offline, used in CI)
    python tools/check_protection.py --live     # GET the real setting, compare, report drift

The recorded snapshot was the third stated gap: it can go stale and cannot notice a
setting being loosened after it was written. The live mode is the fix. It needs a token,
which is a property of the environment, not a hole in the code, so the comparison logic is
unit-tested against synthetic API payloads instead of being trusted because it looks right.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "harness/policy/protection.expected.json"
API = "https://api.github.com/repos/{repo}/branches/{branch}/protection"


def load_expected(path: Path = EXPECTED) -> dict:
    return json.loads(path.read_text())


def normalize(payload: dict) -> dict:
    """Flatten the GitHub protection payload into the keys the policy file compares."""
    checks = payload.get("required_status_checks") or {}
    return {
        "required_context": (checks.get("contexts") or [None])[0],
        "strict": bool(checks.get("strict")),
        "enforce_admins": bool((payload.get("enforce_admins") or {}).get("enabled")),
        "allow_force_pushes": bool((payload.get("allow_force_pushes") or {}).get("enabled")),
        "allow_deletions": bool((payload.get("allow_deletions") or {}).get("enabled")),
    }


def compare(required: dict, observed: dict) -> list[str]:
    problems = []
    for key, want in required.items():
        got = observed.get(key)
        if got != want:
            problems.append(f"{key}: observed {got!r}, required {want!r}")
    return problems


def interpret_http(status: int, body: str = "") -> str:
    if status in (401, 403):
        return (
            f"HTTP {status}: the token cannot read branch protection. Reading it needs "
            f"administration access on the repository; a default Actions GITHUB_TOKEN "
            f"does not have it. Provide a token with admin read, or keep the recorded "
            f"check and note the snapshot date. {body[:120]}"
        )
    if status == 404:
        return (
            f"HTTP 404: no protection configured on this branch, or the branch name is "
            f"wrong. Absence of protection is the finding. {body[:120]}"
        )
    return f"HTTP {status}: unexpected response from the protection endpoint. {body[:120]}"


def fetch_live(repo: str, branch: str, token: str | None, opener=None) -> dict:
    if not token:
        raise RuntimeError(
            "no token in GITHUB_ACCESS_TOKEN; the live check needs one. Run the recorded "
            "check instead (no flag), or export a token with administration read."
        )
    url = API.format(repo=repo, branch=branch)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "assay",
        },
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:  # pragma: no cover - exercised by tests via fake opener
        raise RuntimeError(interpret_http(exc.code, exc.read().decode(errors="replace"))) from exc


def main(argv: list[str]) -> int:
    policy = load_expected()
    required = policy["required"]
    if "--live" in argv:
        token = os.environ.get("GITHUB_ACCESS_TOKEN") or os.environ.get("GITHUB_TOKEN")
        try:
            observed = normalize(fetch_live(policy["repo"], policy["branch"], token))
        except RuntimeError as exc:
            print(f"[UNVERIFIED] {exc}")
            return 2
        problems = compare(required, observed)
        if problems:
            print("[DRIFT] live protection does not match the policy:")
            for p in problems:
                print(f"  - {p}")
            return 1
        print(f"[LIVE PASS] {policy['repo']}@{policy['branch']} matches the policy")
        return 0
    problems = compare(required, policy["recorded"])
    if problems:
        print("[DRIFT] recorded snapshot does not match the policy:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(
        f"[RECORDED PASS] snapshot from {policy.get('recorded_at')} matches the policy. "
        f"Run with --live to check the real setting."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
