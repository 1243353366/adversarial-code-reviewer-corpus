"""Claim-level provenance and the downstream-use gate."""
import copy

from validate_corpus import load, ROOT, check_claim_gate

CLAIMS = load(ROOT / "corpus" / "out" / "claims.json")
META = load(ROOT / "corpus" / "out" / "research-metadata.json")
DOC_IDS = {d["doc_id"] for d in META["documents"]}


def test_manifest_passes_gate():
    assert check_claim_gate(CLAIMS, DOC_IDS) == []


def test_every_claim_points_at_a_known_document():
    for claim in CLAIMS["claims"]:
        assert claim["document_id"] in DOC_IDS


def test_unknown_document_is_caught():
    broken = copy.deepcopy(CLAIMS)
    broken["claims"][0]["document_id"] = "D9"
    assert check_claim_gate(broken, DOC_IDS)


def test_unverified_claim_cannot_be_a_security_rule():
    broken = copy.deepcopy(CLAIMS)
    target = next(c for c in broken["claims"] if c["verification_status"] == "unverified")
    target["permitted_downstream_uses"] = ["security_rule"]
    assert check_claim_gate(broken, DOC_IDS)


def test_interpretation_cannot_be_a_security_rule():
    broken = copy.deepcopy(CLAIMS)
    target = next(c for c in broken["claims"] if c["evidence_type"] == "author_interpretation")
    target["verification_status"] = "verified_against_source"
    target["locator_status"] = "verified"
    target["permitted_downstream_uses"] = ["security_rule"]
    assert check_claim_gate(broken, DOC_IDS)


def test_verified_locator_with_unverified_claim_is_caught():
    broken = copy.deepcopy(CLAIMS)
    target = next(c for c in broken["claims"] if c["verification_status"] == "unverified")
    target["locator_status"] = "verified"
    assert check_claim_gate(broken, DOC_IDS)


def test_no_claim_claims_independent_replication():
    for claim in CLAIMS["claims"]:
        assert claim["replication_status"] == "none"


def test_duplicate_claim_ids_are_caught():
    broken = copy.deepcopy(CLAIMS)
    broken["claims"][1]["claim_id"] = broken["claims"][0]["claim_id"]
    assert check_claim_gate(broken, DOC_IDS)
