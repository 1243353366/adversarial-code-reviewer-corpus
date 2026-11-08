"""Mutation check: a test that passes on both the broken and the fixed code proves nothing.

For each guard the PR #11 review asked for, revert exactly that guard in a scratch copy of
the repository and confirm the test that claims to cover it actually fails. If a revert
leaves the suite green, the test is decorative.

    python tools/mutation_check.py            # run every mutation
    python tools/mutation_check.py --list
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path("tools/validate_corpus.py")
TEST_FILE = "tests/test_rejection_and_witness.py"


@dataclass(frozen=True)
class Mutation:
    name: str
    find: str
    replace: str
    test: str
    finding: str


MUTATIONS = [
    Mutation(
        "witness-ownership-unbound",
        'if owner != claim.get("document_id"):',
        'if False:',
        "test_witness_from_another_document_is_caught",
        "finding 1: retrieval bound to its document",
    ),
    Mutation(
        "witness-host-unchecked",
        'if host != doc_host:',
        'if False:',
        "test_witness_host_must_match_the_document",
        "finding 1: retrieval URL belongs to the document",
    ),
    Mutation(
        "witness-version-unchecked",
        'elif arxiv and doc_arxiv and arxiv != doc_arxiv:',
        'elif False:',
        "test_witness_arxiv_id_must_match_the_document",
        "finding 1: retrieval version belongs to the document",
    ),
    Mutation(
        "rejection-url-unbound",
        'elif retrieval_identity(attempt.get("url", ""))[0] != retrieval_identity(r.get("url", ""))[0]:',
        'elif False:',
        "test_unrelated_attempt_url_is_caught",
        "finding 2: an attempt must point at the refused source",
    ),
    Mutation(
        "status-range-unchecked",
        "if not isinstance(status, int) or not 100 <= status <= 599:",
        "if False:",
        "test_status_outside_http_range_is_caught",
        "finding 2: status codes must be real HTTP codes",
    ),
    Mutation(
        "evidence-threshold-lowered",
        "len(evidence) < 80",
        "len(evidence) < 40",
        "test_thin_evidence_is_caught",
        "finding 2: evidence threshold is evidentiary, not cosmetic",
    ),
    Mutation(
        "evidence-untied-to-status",
        "if statuses and not any(str(s) in evidence for s in statuses):",
        "if False:",
        "test_evidence_must_mention_the_status_it_claims",
        "finding 2: evidence must name the result it rests on",
    ),
    Mutation(
        "url-prefix-test",
        "if not host:",
        "if False:",
        "test_weak_urls_are_rejected[https---]",
        "finding 3: a URL needs a host, not a prefix",
    ),
    Mutation(
        "single-manifest-loader",
        'for path in sorted(manifest_dir.glob("*.json")):',
        'for path in sorted(manifest_dir.glob("D3.json")):',
        "test_second_manifest_is_loaded_not_just_d3",
        "finding 6: every manifest is loaded",
    ),
]


def run(mutation: Mutation) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        target = work / TARGET
        source = target.read_text()
        if mutation.find not in source:
            return False, "anchor not found; the mutation no longer applies"
        target.write_text(source.replace(mutation.find, mutation.replace, 1))
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"{TEST_FILE}::{mutation.test}"],
            cwd=work, capture_output=True, text=True,
        )
        if proc.returncode == 0:
            return False, "suite stayed green, so that test does not cover this guard"
        return True, "test failed as required"


def main(argv: list[str]) -> int:
    if "--list" in argv:
        for m in MUTATIONS:
            print(f"{m.name:28} {m.test:52} {m.finding}")
        return 0
    failures = 0
    for m in MUTATIONS:
        ok, why = run(m)
        print(f"[{'CAUGHT' if ok else 'MISSED'}] {m.name:28} {why}")
        failures += 0 if ok else 1
    print(f"\n{len(MUTATIONS) - failures}/{len(MUTATIONS)} guards proven by a failing test")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
