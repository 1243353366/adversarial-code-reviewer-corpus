"""Metadata must be schema-valid, and the schema must actually reject bad input."""
import copy

import pytest

from validate_corpus import load, schema_errors, ROOT

SCHEMA = load(ROOT / "schemas" / "research-metadata.schema.json")
META = load(ROOT / "corpus" / "out" / "research-metadata.json")


def test_metadata_conforms_to_schema():
    assert schema_errors(META, SCHEMA) == []


def test_reproducibility_enums_are_normalised():
    for doc in META["documents"]:
        rep = doc["reproducibility"]
        assert isinstance(rep["independently_replicated"], bool), doc["doc_id"]
        assert rep["code_available"] in {"yes", "no", "unconfirmed", "not_stated"}
        assert rep["search_strings_reported"] in {"yes", "partially", "no", "not_stated"}


def test_missing_reproducibility_block_is_rejected():
    broken = copy.deepcopy(META)
    del broken["documents"][0]["reproducibility"]
    assert schema_errors(broken, SCHEMA)


def test_boolean_code_availability_is_rejected():
    """The original defect: code_available was a boolean in one record, a string in another."""
    broken = copy.deepcopy(META)
    broken["documents"][0]["reproducibility"]["code_available"] = True
    assert schema_errors(broken, SCHEMA)


def test_unknown_peer_review_tier_is_rejected():
    broken = copy.deepcopy(META)
    broken["documents"][0]["peer_review_tier"] = "probably_published"
    assert schema_errors(broken, SCHEMA)


@pytest.mark.parametrize("bad_id", ["D", "d1", "DOC1", "1"])
def test_doc_id_format_is_enforced(bad_id):
    broken = copy.deepcopy(META)
    broken["documents"][0]["doc_id"] = bad_id
    assert schema_errors(broken, SCHEMA)
