"""Provenance integrity: identifiers agree with URLs, tiers agree with the roll-up."""
import copy

from validate_corpus import (
    load,
    ROOT,
    check_arxiv_url_consistency,
    check_peer_review_tiers,
    check_unique_doc_ids,
)

META = load(ROOT / "corpus" / "out" / "research-metadata.json")


def test_doc_ids_unique():
    assert check_unique_doc_ids(META) == []


def test_arxiv_ids_match_source_urls():
    assert check_arxiv_url_consistency(META) == []


def test_mismatched_arxiv_id_is_caught():
    broken = copy.deepcopy(META)
    broken["documents"][0]["source_url"] = "https://arxiv.org/abs/2401.00001"
    assert check_arxiv_url_consistency(broken)


def test_non_arxiv_url_is_caught():
    broken = copy.deepcopy(META)
    broken["documents"][0]["source_url"] = "https://example.com/paper.pdf"
    assert check_arxiv_url_consistency(broken)


def test_peer_review_rollup_agrees_with_documents():
    assert check_peer_review_tiers(META) == []


def test_tier_drift_is_caught():
    """The original defect: a document claimed one status while the report said another."""
    broken = copy.deepcopy(META)
    broken["documents"][0]["peer_review_tier"] = "publisher_confirmed"
    assert check_peer_review_tiers(broken)


def test_nothing_is_publisher_confirmed():
    confirmed = META["corpus_level_observations"]["peer_review_tiers"]["publisher_confirmed"]
    assert confirmed == [], "no publisher record has been opened for any source"


def test_licensing_guard_scopes_text_files_to_the_corpus_tree():
    from validate_corpus import check_no_document_bodies

    assert check_no_document_bodies(["corpus/txt_2508.04448.txt"])
    assert check_no_document_bodies(["corpus/raw/paper.html"])
    assert check_no_document_bodies(["docs/paper.pdf"])
    assert check_no_document_bodies(["requirements-dev.txt"]) == []
    assert check_no_document_bodies(["corpus/out/claims.json"]) == []
