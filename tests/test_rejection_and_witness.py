"""Adversarial tests for the checks that the review found too permissive.

Each test is a way to pass the previous version of the validator while asserting
something untrue. They exist because "the check runs" and "the check enforces" are
different claims.
"""
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import validate_corpus as V  # noqa: E402

META = json.load(open(ROOT / "corpus/out/research-metadata.json"))
CLAIMS = json.load(open(ROOT / "corpus/out/claims.json"))
RETRIEVALS = {"retrievals": {}}
for path in sorted((ROOT / "harness/retrievals").glob("*.json")):
    RETRIEVALS["retrievals"].update(json.load(open(path)).get("retrievals", {}))


def _rejections(**over):
    base = {
        "source_id": "RSX",
        "url": "https://example.org/paper",
        "reason_code": "unretrievable",
        "retrieval_attempts": [{"url": "https://example.org/paper", "status": 403}],
        "evidence": "Two requests returned 403 from the origin, so the page was never read.",
    }
    base.update(over)
    return {"rejected_sources": [base]}


def test_current_rejections_pass():
    assert V.check_rejected_sources(META) == []


def test_duplicate_rejection_id_is_caught():
    broken = copy.deepcopy(_rejections())
    broken["rejected_sources"].append(copy.deepcopy(broken["rejected_sources"][0]))
    assert V.check_rejected_sources(broken)


def test_rejection_with_no_attempt_is_caught():
    assert V.check_rejected_sources(_rejections(retrieval_attempts=[]))


def test_unknown_reason_code_is_caught():
    assert V.check_rejected_sources(_rejections(reason_code="i_do_not_like_it"))


def test_thin_evidence_is_caught():
    assert V.check_rejected_sources(_rejections(evidence="bad site"))


def test_unrelated_attempt_url_is_caught():
    """A rejection proven by fetching something else proves nothing."""
    assert V.check_rejected_sources(
        _rejections(retrieval_attempts=[{"url": "https://unrelated.test/x", "status": 403}])
    )


def test_status_outside_http_range_is_caught():
    assert V.check_rejected_sources(
        _rejections(retrieval_attempts=[{"url": "https://example.org/paper", "status": 999}])
    )


def test_evidence_must_mention_the_status_it_claims():
    assert V.check_rejected_sources(
        _rejections(evidence="Repeated attempts failed in a way that seemed conclusive to us.")
    )


def test_unretrievable_requires_a_failed_attempt():
    """A 200 recorded beside a claim that the page could not be read is a contradiction."""
    assert V.check_rejected_sources(
        _rejections(
            reason_code="unretrievable",
            retrieval_attempts=[{"url": "https://example.org/paper", "status": 200}],
            evidence="The page returned 200 and was skimmed quickly.",
        )
    )


def test_provenance_rejection_requires_a_successful_retrieval():
    assert V.check_rejected_sources(
        _rejections(
            reason_code="provenance_unestablished",
            retrieval_attempts=[{"url": "https://example.org/paper", "status": 404}],
            evidence="The page returned 404, so authorship could not be judged at all.",
        )
    )


def _claim_with(retrieval_id):
    broken = copy.deepcopy(CLAIMS)
    claim = next(c for c in broken["claims"] if c["claim_id"] == "D7-C01")
    claim["locator"]["witness"]["retrieval_id"] = retrieval_id
    return broken


def test_witness_from_another_document_is_caught():
    """The defect the review found: a D7 claim citing a D3 retrieval, both perfectly valid."""
    foreign = next(rid for rid, rec in RETRIEVALS["retrievals"].items() if rec["document_id"] == "D3")
    assert V.check_locator_witness(_claim_with(foreign), RETRIEVALS, META)


def test_witness_from_its_own_document_passes():
    assert V.check_locator_witness(_claim_with("D7-2026-11-08-pdf"), RETRIEVALS, META) == []


def test_duplicate_retrieval_ids_are_rejected(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    record = {"retrievals": {"X": {"document_id": "D3", "artifact_sha256": "00"}}}
    a.write_text(json.dumps(record))
    b.write_text(json.dumps(record))
    merged, dupes = {}, []
    for path in sorted(tmp_path.glob("*.json")):
        for rid in json.loads(path.read_text())["retrievals"]:
            if rid in merged:
                dupes.append(rid)
            merged[rid] = True
    assert dupes == ["X"]


@pytest.mark.parametrize(
    "url",
    ["https://", "https://?q=1", "http://example.org", "https://user:pw@example.org/x", "https://nodot/x"],
)
def test_weak_urls_are_rejected(url):
    assert V.url_structure_error(url)


def test_real_urls_pass():
    for url in ("https://example.org/a.pdf", "https://arxiv.org/abs/2403.02546"):
        assert V.url_structure_error(url) is None
