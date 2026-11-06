"""The live protection check, tested against synthetic payloads.

The recorded snapshot was a stated gap: it cannot notice a setting being loosened later.
Live mode closes it, but only if the normalisation and comparison are right, and neither
can be exercised in CI against a real admin endpoint. So both are tested against payloads
shaped like the API's.
"""
import pytest

import check_protection as CP

REQUIRED = {
    "required_context": "corpus",
    "strict": True,
    "enforce_admins": True,
    "allow_force_pushes": False,
    "allow_deletions": False,
}


def payload(**over):
    base = {
        "required_status_checks": {"contexts": ["corpus"], "strict": True},
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }
    base.update(over)
    return base


def test_normalizes_a_matching_payload():
    assert CP.compare(REQUIRED, CP.normalize(payload())) == []


def test_detects_admin_bypass_turned_back_on():
    observed = CP.normalize(payload(enforce_admins={"enabled": False}))
    assert any("enforce_admins" in p for p in CP.compare(REQUIRED, observed))


def test_detects_context_renamed_to_the_workflow():
    observed = CP.normalize(payload(required_status_checks={"contexts": ["validate"], "strict": True}))
    assert any("required_context" in p for p in CP.compare(REQUIRED, observed))


def test_detects_force_push_allowed():
    observed = CP.normalize(payload(allow_force_pushes={"enabled": True}))
    assert any("allow_force_pushes" in p for p in CP.compare(REQUIRED, observed))


def test_detects_strict_mode_dropped():
    observed = CP.normalize(payload(required_status_checks={"contexts": ["corpus"], "strict": False}))
    assert any("strict" in p for p in CP.compare(REQUIRED, observed))


def test_missing_token_names_the_next_step(monkeypatch):
    monkeypatch.delenv("GITHUB_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(RuntimeError) as exc:
        CP.fetch_live("o/r", "main", None)
    assert "token" in str(exc.value).lower()


def test_forbidden_token_explains_the_permission():
    message = CP.interpret_http(403, '{"message":"Resource not accessible by integration"}')
    assert "administration" in message
    assert "403" in message


def test_missing_protection_is_reported_as_a_finding():
    assert "no protection" in CP.interpret_http(404).lower()


def test_recorded_check_runs_against_the_committed_policy():
    assert CP.main([]) == 0
