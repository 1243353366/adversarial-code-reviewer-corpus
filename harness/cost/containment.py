"""Adversarial cost containment.

The listener should be expensive to abuse and cheap to use honestly. That is a ratio
question, not a threshold question: what did this interaction cost against what it asked
for.

Three axes, each consumed/requested in comparable units:

    bytes : response bytes / request bytes
    cpu   : microseconds of CPU / request byte
    queue : frames left outstanding / frames in the window

Two details decide whether this works at all. Request size has a floor of one byte, so an
empty request produces a large ratio instead of a division error or a NaN that compares
false against every limit. And escalation needs hysteresis, because one slow sample is
noise and five in a window is a pattern.

Nothing here executes a peer's command, sends anything back except a fixed synthetic
reply, or inflicts load on the sender. Containment is local.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

REQUEST_FLOOR_BYTES = 1
WINDOW = 20


@dataclass(frozen=True)
class Sample:
    """One request/response exchange, as measured by the caller."""

    request_bytes: int
    response_bytes: int
    cpu_seconds: float
    queue_growth: int = 0


@dataclass(frozen=True)
class Ratios:
    bytes_amp: float
    cpu_amp: float
    queue_amp: float

    def breached(self, budget: "Budget") -> list[str]:
        out = []
        if self.bytes_amp > budget.max_bytes_amp:
            out.append("bytes")
        if self.cpu_amp > budget.max_cpu_amp:
            out.append("cpu")
        if self.queue_amp > budget.max_queue_amp:
            out.append("queue")
        return out


@dataclass(frozen=True)
class Budget:
    max_bytes_amp: float = 20.0
    max_cpu_amp: float = 50.0        # microseconds of CPU per request byte
    max_queue_amp: float = 3.0       # outstanding frames per frame in the window
    window: int = WINDOW
    quarantine_after: int = 3
    terminate_after: int = 5
    deny_seconds: float = 300.0


OK, THROTTLE, QUARANTINE, TERMINATE = "ok", "throttle", "quarantine", "terminate"


@dataclass
class Decision:
    action: str
    reasons: tuple[str, ...] = ()
    ratios: Ratios | None = None
    run_handler: bool = True
    reply: bytes | None = None


def measure(sample: Sample) -> Ratios:
    """Never returns NaN or infinity. An empty request is cheap only if the work was too."""
    req = max(sample.request_bytes, REQUEST_FLOOR_BYTES)
    return Ratios(
        bytes_amp=sample.response_bytes / req,
        cpu_amp=(sample.cpu_seconds * 1_000_000.0) / req,
        queue_amp=float(sample.queue_growth),
    )


SYNTHETIC_REPLY = b'{"status":"accepted"}'


@dataclass
class ConnectionState:
    breaches: int = 0
    samples: int = 0
    worst: Ratios | None = None
    history: deque = field(default_factory=lambda: deque(maxlen=WINDOW))


class Guard:
    """Per-connection cost accounting with escalation that survives a single outlier."""

    def __init__(self, budget: Budget | None = None, clock=None):
        self.budget = budget or Budget()
        self.clock = clock or (lambda: 0.0)
        self._state: dict[str, ConnectionState] = defaultdict(ConnectionState)
        self._denied: dict[str, float] = {}
        self.counts = defaultdict(int)

    # -- decisions ---------------------------------------------------------------
    def observe(self, conn: str, sample: Sample) -> Decision:
        if conn in self._denied:
            if self.clock() < self._denied[conn]:
                self.counts["denied"] += 1
                return Decision(TERMINATE, ("denied",), None, run_handler=False)
            del self._denied[conn]
            self._state[conn] = ConnectionState()

        st = self._state[conn]
        ratios = measure(sample)
        st.samples += 1
        st.history.append(ratios)
        if st.worst is None or ratios.bytes_amp > st.worst.bytes_amp:
            st.worst = ratios

        breaches = ratios.breached(self.budget)
        if breaches:
            st.breaches += 1
            reasons = tuple(breaches)
            if st.breaches >= self.budget.terminate_after:
                self._denied[conn] = self.clock() + self.budget.deny_seconds
                self.counts["terminated"] += 1
                return Decision(TERMINATE, reasons, ratios, run_handler=False)
            if st.breaches >= self.budget.quarantine_after:
                self.counts["quarantined"] += 1
                return Decision(QUARANTINE, reasons, ratios, run_handler=False, reply=SYNTHETIC_REPLY)
            self.counts["throttled"] += 1
            return Decision(THROTTLE, reasons, ratios, run_handler=True)

        if st.breaches:
            st.breaches -= 1  # a cheap sample buys back one strike, so bursts cannot accumulate forever
        self.counts["ok"] += 1
        return Decision(OK, (), ratios)

    # -- reporting ---------------------------------------------------------------
    def summary(self) -> list[dict]:
        """The metric this exists to produce: amplification per connection."""
        rows = []
        for conn, st in sorted(self._state.items()):
            if not st.samples:
                continue
            rows.append({
                "conn": conn,
                "samples": st.samples,
                "breaches": st.breaches,
                "bytes_amp": round(st.worst.bytes_amp, 3) if st.worst else 0.0,
                "cpu_amp": round(st.worst.cpu_amp, 3) if st.worst else 0.0,
                "queue_amp": round(st.worst.queue_amp, 3) if st.worst else 0.0,
            })
        return rows


def amplification_report(guard: Guard) -> str:
    rows = guard.summary()
    if not rows:
        return "no interactions"
    head = "conn        samples breaches  bytes_amp  cpu_amp  queue_amp"
    body = "\n".join(
        f"{r['conn']:<12}{r['samples']:>7}{r['breaches']:>9}{r['bytes_amp']:>11}{r['cpu_amp']:>9}{r['queue_amp']:>10}"
        for r in rows
    )
    return f"{head}\n{body}"
