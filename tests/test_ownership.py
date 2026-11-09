"""Ownership agreement across filesystem, canary, registry and hooks.

Each test either proves the four agree, or corrupts one of them and requires the audit to notice.
A clean audit on a corrupted system would be the failure this module exists to prevent.
"""

from __future__ import annotations

from harness.deception import mirror as mx_mod
from harness.deception import ownership as own


def _two_sessions(variation: bool = False):
    mirror = mx_mod.Mirror(variation=variation)
    a = mirror.connect("198.51.100.41:41412")
    b = mirror.connect("198.51.100.42:41412")
    return mirror, a, b


def test_two_sessions_with_the_same_seed_agree_on_ownership():
    mirror, a, b = _two_sessions()
    assert a.seed == b.seed
    assert own.audit(mirror) == []
    tokens = {c_.token for c_ in mirror.canaries.by_session.values()}
    assert len(tokens) == 2


def test_a_real_read_fires_only_its_owner_and_audit_stays_clean():
    mirror, a, b = _two_sessions()
    a.send("cat /var/www/app/.env\n")
    assert len(mirror.canaries.by_session[a.session_id].touches) == 1
    assert mirror.canaries.by_session[b.session_id].touches == []
    assert own.audit(mirror) == []


def test_a_scripted_intrusion_never_crosses_sessions():
    mirror, a, b = _two_sessions()
    a.send("cat /home/deploy/.aws/credentials\n")
    b.send("cat /var/www/app/.env\n")
    for sid in (a.session_id, b.session_id):
        canary = mirror.canaries.by_session[sid]
        assert [t["seen_in"] for t in canary.touches] == [sid]
    assert own.audit(mirror) == []


def test_reuse_links_sessions_without_becoming_a_file_read():
    mirror, a, b = _two_sessions()
    token = mirror.canaries.by_session[a.session_id].token
    b.send("export AWS_KEY=" + token + "\n")
    links = mirror.canaries.links()
    assert links and links[0]["identity_claim"] == "not established"
    assert own.audit(mirror) == []


def test_a_canary_planted_in_the_wrong_filesystem_is_reported():
    mirror, a, b = _two_sessions()
    wrong = mirror.canaries.by_session[b.session_id]
    a.env.files["/var/www/app/.env"] = wrong.token + "\n"
    problems = own.audit(mirror)
    assert any("contains" in p for p in problems), problems


def test_duplicate_tokens_are_reported():
    mirror, a, b = _two_sessions()
    shared = mirror.canaries.by_session[a.session_id].token
    mirror.canaries.by_session[b.session_id].token = shared
    assert any("shared by" in p for p in own.audit(mirror))


def test_a_missing_canary_is_reported():
    mirror, a, b = _two_sessions()
    del mirror.canaries.by_session[b.session_id]
    assert any("no canary" in p for p in own.audit(mirror))


def test_a_cross_session_file_read_attribution_is_reported():
    mirror, a, b = _two_sessions()
    mirror.canaries.by_session[a.session_id].touch(
        "file_read", "read by someone else", seen_in=b.session_id)
    assert any("attributed as its own" in p for p in own.audit(mirror))


def test_a_quiet_session_produces_no_alerts_and_no_problems():
    mirror, a, b = _two_sessions()
    assert own.audit(mirror) == []
    assert mirror.canaries.report()["touches"] == 0
