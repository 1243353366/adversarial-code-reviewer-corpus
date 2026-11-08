"""Self-referential input: the listener has to know which of its own words it is hearing."""
import pytest

from harness.provenance import INTERNAL, REMOTE, internal_capability
from harness.provenance.listener import GuardedListener, NaiveListener


def test_a_peer_cannot_claim_internal_origin():
    """Identity confusion: the message body says internal, and the body is the only witness."""
    naive = NaiveListener()
    naive.transport_in({"id": "1", "origin": INTERNAL})
    naive.run()
    assert naive.result.events[0][0] == INTERNAL  # believed the peer

    guarded = GuardedListener()
    guarded.transport_in({"id": "1", "origin": INTERNAL})
    res = guarded.run()
    assert ("claimed_internal_origin" in res.rejected)
    assert res.events[0][0] == REMOTE  # believed the wire


def test_internal_enqueue_needs_the_capability_object_not_the_word():
    naive = NaiveListener()
    naive.internal_in({"id": "2"})
    assert naive.run().processed > 100  # amplification, not acceptance

    guarded = GuardedListener()
    guarded.internal_in({"id": "2"})  # no capability object
    assert "internal_enqueue_without_capability" in guarded.result.rejected


def test_the_real_capability_is_accepted():
    guarded = GuardedListener()
    guarded.internal_in({"id": "3"}, cap=internal_capability())
    assert guarded.run().processed >= 1


def test_feedback_loop_is_bounded_where_the_naive_one_is_not():
    naive = NaiveListener(capacity=200)
    naive.transport_in({"id": "loop"})
    n = naive.run()
    assert n.processed > 50  # amplification

    guarded = GuardedListener(capacity=200)
    guarded.transport_in({"id": "loop"})
    g = guarded.run()
    assert g.processed <= 2
    assert "hop_limit" in g.rejected


def test_provenance_of_a_reply_is_internal_and_inherits_ancestry():
    guarded = GuardedListener()
    guarded.transport_in({"id": "p1"})
    guarded.run()
    # the reply was processed as internal, on the same connection
    assert [o for o, _ in guarded.result.events] == [REMOTE, INTERNAL]


def test_ancestry_cycle_is_refused():
    guarded = GuardedListener()
    guarded._enqueue(__import__("harness.provenance", fromlist=["Envelope"]).Envelope(
        msg={"id": "a"}, origin=REMOTE, conn_id="c", ancestry=("a",)
    ))
    res = guarded.run()
    assert "ancestry_cycle" in res.rejected


def test_queue_capacity_is_counted_not_silently_dropped():
    guarded = GuardedListener(capacity=2)
    for i in range(6):
        guarded.transport_in({"id": str(i)})
    guarded.run()
    assert guarded.result.suppressed > 0


def test_same_block_is_not_processed_twice_by_both_paths():
    """A response enqueued internally must not also arrive as remote input."""
    guarded = GuardedListener()
    guarded.transport_in({"id": "x"})
    guarded.run()
    remote_events = [e for e in guarded.result.events if e[0] == REMOTE]
    assert len(remote_events) == 1


def test_rejects_are_named_not_silent():
    guarded = GuardedListener()
    guarded.transport_in({"id": "9", "origin": INTERNAL})
    res = guarded.run()
    assert res.rejected and all(isinstance(r, str) and r for r in res.rejected)
