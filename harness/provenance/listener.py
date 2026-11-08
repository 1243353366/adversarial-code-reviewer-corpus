"""Two listeners over the same queue: one that believes the message, one that believes the wire."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from . import INTERNAL, REMOTE, Envelope, internal_capability

MAX_HOPS = 1


@dataclass
class Result:
    processed: int = 0
    suppressed: int = 0
    rejected: list[str] = field(default_factory=list)
    queue_depth: int = 0
    events: list[tuple[str, str]] = field(default_factory=list)


class NaiveListener:
    """Origin comes from the message body, and a response goes back into the same queue.

    This is the shape of the defect rather than a caricature: reading `msg["origin"]` is
    how provenance usually arrives in real handlers, and re-enqueueing a reply is how a
    feedback loop starts.
    """

    def __init__(self, capacity: int = 50):
        self.queue: deque[dict] = deque(maxlen=capacity)
        self.result = Result()

    def transport_in(self, msg: dict, conn_id: str = "c1") -> None:
        self.queue.append(msg)

    def internal_in(self, msg: dict, conn_id: str = "c1") -> None:
        self.queue.append(msg)

    def run(self) -> Result:
        hops = 0
        while self.queue and hops < 1000:
            msg = self.queue.popleft()
            hops += 1
            origin = str(msg.get("origin", REMOTE))
            self.result.events.append((origin, str(msg.get("id"))))
            self.result.processed += 1
            reply = {"id": f"{msg.get('id')}-r", "origin": origin, "reply": True}
            self.queue.append(reply)  # the loop closes here
        self.result.queue_depth = len(self.queue)
        return self.result


class GuardedListener:
    def __init__(self, capacity: int = 50):
        self.queue: deque[Envelope] = deque(maxlen=capacity)
        self.result = Result()

    def transport_in(self, msg: dict, conn_id: str = "c1") -> None:
        # Origin comes from the transport, not from the bytes.
        self._enqueue(Envelope(msg=msg, origin=REMOTE, conn_id=conn_id))

    def internal_in(self, msg: dict, conn_id: str = "c1", cap=None) -> None:
        if cap is not internal_capability():
            self.reject("internal_enqueue_without_capability")
            return
        self._enqueue(Envelope(msg=msg, origin=INTERNAL, conn_id=conn_id, cap=cap))

    def _enqueue(self, env: Envelope) -> None:
        if len(self.queue) == self.queue.maxlen:
            self.result.suppressed += 1
        self.queue.append(env)

    def reject(self, reason: str) -> None:
        self.result.rejected.append(reason)

    def run(self) -> Result:
        while self.queue:
            env = self.queue.popleft()
            msg = env.msg
            if env.is_internal() and env.origin != INTERNAL:
                self.reject("provenance_conflict")
                continue
            if len(env.ancestry) > MAX_HOPS:
                self.reject("hop_limit")
                continue
            if str(msg.get("id")) in env.ancestry:
                self.reject("ancestry_cycle")
                continue
            if env.origin == REMOTE and msg.get("origin") == INTERNAL:
                # A remote peer claiming to be this process. Counted, never trusted.
                self.reject("claimed_internal_origin")
            self.result.events.append((env.origin, str(msg.get("id"))))
            self.result.processed += 1
            self._enqueue(env.child({"id": f"{msg.get('id')}-r", "reply": True}))
        self.result.queue_depth = len(self.queue)
        return self.result
