"""Adversarial tests: do the validators catch deliberate regressions?

The previous suite proved the checks reject the defects that were already found. That is
the easy half. This file asks the harder question: if someone wanted a fabricated claim
to ship, which of their moves does the validator actually stop?

Two kinds of test live here. `test_blocks_*` assert an attack is caught. `test_admits_*`
assert an attack succeeds, on purpose, so the blind spot is recorded in code rather than
discovered later by a reader who trusted the checks too much.
"""
import copy

from validate_corpus import (
    load,
    ROOT,
    schema_errors,
    check_arxiv_url_consistency,
    check_claim_gate,
    check_corpus_counts,
    check_extension_keys,
    check_license_consistency,
    check_locator_resolution,
    check_locator_witness,
    check_peer_review_tiers,
    check_replication_claims,
    check_status_fields,
    check_status_language,
)

SCHEMA = load(ROOT / "schemas" / "research-metadata.schema.json")
CLAIM_SCHEMA = load(ROOT / "schemas" / "claim.schema.json")
META = load(ROOT / "corpus" / "out" / "research-metadata.json")
CLAIMS = load(ROOT / "corpus" / "out" / "claims.json")
DOC_IDS = {d["doc_id"] for d in META["documents"]}


def _first_unverified(claims):
    return next(c for c in claims["claims"] if c["verification_status"] == "unverified")


# ---------------------------------------------------------------- attacks blocked


def test_blocks_unverified_claim_promoted_to_security_rule():
    """The headline attack: take the weakest claim and ship it as a detector."""
    broken = copy.deepcopy(CLAIMS)
    target = _first_unverified(broken)
    target["permitted_downstream_uses"] = ["security_rule"]
    assert check_claim_gate(broken, DOC_IDS)


def test_blocks_interpretation_wearing_a_verified_label():
    broken = copy.deepcopy(CLAIMS)
    target = next(c for c in broken["claims"] if c["evidence_type"] == "author_interpretation")
    target["verification_status"] = "verified_against_source"
    target["locator_status"] = "verified"
    target["permitted_downstream_uses"] = ["security_rule"]
    assert check_claim_gate(broken, DOC_IDS)


def test_blocks_fabricated_replication():
    """Claiming someone else replicated the result, which no document records."""
    broken = copy.deepcopy(CLAIMS)
    broken["claims"][0]["replication_status"] = "independent"
    assert check_replication_claims(broken, META)


def test_blocks_invented_locator_on_an_unavailable_claim():
    broken = copy.deepcopy(CLAIMS)
    target = next(c for c in broken["claims"] if c["locator_status"] == "unavailable")
    target["locator_status"] = "verified"
    assert check_locator_resolution(broken)


def test_blocks_smuggled_verification_field():
    """An adversary cannot add `verified: true` to a document record."""
    broken = copy.deepcopy(META)
    broken["documents"][0]["verified"] = True
    assert check_extension_keys(broken)


def test_blocks_namespaced_fields_are_the_only_extension_route():
    broken = copy.deepcopy(META)
    broken["documents"][0]["x_internal_note"] = "fine"
    assert check_extension_keys(broken) == []


def test_blocks_inflated_coverage_counts():
    broken = copy.deepcopy(META)
    broken["corpus_level_observations"]["documents_verified"] = 9
    assert check_corpus_counts(broken)


def test_blocks_document_dropped_from_redistribution_partition():
    broken = copy.deepcopy(META)
    broken["corpus_level_observations"]["non_redistributable"].remove("D5")
    assert check_corpus_counts(broken)


def test_blocks_non_permissive_source_moved_into_redistributable():
    """The licensing failure the project would actually be sued over."""
    broken = copy.deepcopy(META)
    broken["corpus_level_observations"]["redistributable"].append("D1")
    broken["corpus_level_observations"]["non_redistributable"].remove("D1")
    assert check_license_consistency(broken)


def test_blocks_unqualified_publication_claim_in_markdown(tmp_path):
    doc = tmp_path / "notes.md"
    doc.write_text("| D1 | Some paper | 2507.22659 | Accepted at TOSEM |\n")
    assert check_status_language([str(doc)])


def test_blocks_qualified_publication_claim_is_allowed(tmp_path):
    doc = tmp_path / "notes.md"
    doc.write_text("| D1 | Some paper | 2507.22659 | Accepted TOSEM per manuscript header |\n")
    assert check_status_language([str(doc)]) == []


def test_blocks_negated_publication_phrase(tmp_path):
    doc = tmp_path / "notes.md"
    doc.write_text("This is a degree thesis adapted to a preprint, not a peer-reviewed publication.\n")
    assert check_status_language([str(doc)]) == []


def test_blocks_claim_pointing_at_deleted_document():
    broken = copy.deepcopy(CLAIMS)
    broken["claims"][0]["document_id"] = "D99"
    assert check_claim_gate(broken, DOC_IDS)


def test_blocks_swapped_arxiv_id_without_swapping_url():
    broken = copy.deepcopy(META)
    broken["documents"][0]["arxiv_id"] = "2401.00001"
    assert check_arxiv_url_consistency(broken)


def test_blocks_removal_of_a_required_field():
    broken = copy.deepcopy(META)
    del broken["documents"][0]["evidence_status"]
    assert schema_errors(broken, SCHEMA)


def test_blocks_malformed_claim_schema():
    broken = copy.deepcopy(CLAIMS)
    broken["claims"][0]["permitted_downstream_uses"] = ["production_rule"]
    assert schema_errors(broken, CLAIM_SCHEMA)


# ---------------------------------------------------- attacks that still get through
#
# These are recorded deliberately. Each is a real hole with a stated reason and a
# stated route to closing it. A validator whose limits are unwritten invites false
# confidence in exactly the way this project exists to punish.


def test_admits_coordinated_peer_review_downgrade():
    """Blind spot: no external anchor. The validator checks internal agreement only."""
    broken = copy.deepcopy(META)
    rollup = broken["corpus_level_observations"]["peer_review_tiers"]
    for doc in broken["documents"]:
        doc["peer_review_tier"] = "unreviewed"
    for key in rollup:
        rollup[key] = []
    rollup["unreviewed"] = [d["doc_id"] for d in broken["documents"]]
    assert check_peer_review_tiers(broken) == []


def test_admits_wholesale_source_substitution():
    """Blind spot: no content fingerprint. Swap every identifier consistently and pass.

    Closing this needs a fetch of the arXiv record and a title comparison, which is a
    network check and does not belong inside an offline validator.
    """
    broken = copy.deepcopy(META)
    doc = broken["documents"][0]
    doc["arxiv_id"] = "2401.00001"
    doc["source_url"] = "https://arxiv.org/abs/2401.00001"
    doc["title"] = "An Entirely Different Paper With A Plausible Title"
    assert check_arxiv_url_consistency(broken) == []
    assert schema_errors(broken, SCHEMA) == []


def test_plausible_invented_locator_needs_a_witness_to_catch():
    """The section-existence check cannot tell an invented section from a real one.

    This was an admitted blind spot. It is now caught one layer up, by requiring a verbatim
    witness with an offset and a retrieval hash, so the assertion moved from "we cannot see
    it" to "we see it only where a witness is absent". Both halves are asserted here so
    neither can be quietly dropped.
    """
    claims = copy.deepcopy(CLAIMS)
    for cl in claims["claims"]:
        if cl["locator_status"] == "unavailable":
            cl["locator_status"] = "verified"
            cl["locator"]["section"] = "Section 4.2"
            break
    assert not check_locator_resolution(claims), "section-existence check should not see it"
    retrievals = {"retrievals": {}}
    assert check_locator_witness(claims, retrievals), "witness check should block it"


def test_admits_trivially_true_claim_text():
    """Blind spot: schema validates shape, not meaning.

    A tautology passes every field check. Only a reviewer reading the claim catches it.
    """
    broken = copy.deepcopy(CLAIMS)
    broken["claims"][0]["claim_text"] = "The paper exists and contains words about the topic."
    assert schema_errors(broken, CLAIM_SCHEMA) == []


def test_blocks_quoted_example_inside_backticks_is_allowed(tmp_path):
    """The check has produced two false positives, both from quoting its own target."""
    doc = tmp_path / "notes.md"
    doc.write_text(
        "| Mutation | Caught |\n"
        "|---|---|\n"
        "| `| D1 | ... | Accepted at TOSEM |` inserted into a README | No |\n"
    )
    assert check_status_language([str(doc)]) == []


def test_blocks_fenced_block_is_allowed(tmp_path):
    doc = tmp_path / "notes.md"
    doc.write_text("```\nAccepted at TOSEM\n```\n")
    assert check_status_language([str(doc)]) == []


def test_blocks_unqualified_claim_in_a_json_status_field():
    """The markdown lint could not see these, and two of them asserted peer review
    with the basis living in a different field."""
    broken = copy.deepcopy(META)
    broken["documents"][3]["peer_review_status"] = "peer reviewed, ESORICS 2024"
    assert check_status_fields(broken)


def test_blocks_tier_without_a_stated_basis():
    broken = copy.deepcopy(META)
    broken["documents"][1]["peer_review_status"] = "published in CSUR"
    assert check_status_fields(broken)


def test_blocks_clean_status_fields():
    assert check_status_fields(META) == []
