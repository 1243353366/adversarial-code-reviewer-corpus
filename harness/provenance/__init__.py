"""Provenance confusion: can a listener lose track of who produced a message?

Three failures, one root cause. The listener keeps the origin of a message in the
message, so anything able to write a message can claim any origin.

The fix is not a better field. Origin is assigned by the transport that delivered the
bytes, once, at ingress, and the internal capability is an object identity rather than a
string, so a peer cannot spell it into existence.
"""
from __future__ import annotations

from dataclasses import dataclass, field

REMOTE = "remote"
INTERNAL = "internal"

# Module-private sentinel. Equality is identity, so no serialized value can equal it.
_INTERNAL_CAP = object()


def internal_capability():
    """Handed only to in-process producers. Never serialized, never logged."""
    return _INTERNAL_CAP


@dataclass(frozen=True)
class Envelope:
    msg: dict
    origin: str
    conn_id: str
    ancestry: tuple[str, ...] = ()
    cap: object | None = field(default=None, repr=False)

    def is_internal(self) -> bool:
        return self.cap is _INTERNAL_CAP

    def child(self, msg: dict) -> "Envelope":
        """A response, with its ancestry extended. Provenance travels forward."""
        return Envelope(
            msg=msg,
            origin=INTERNAL,
            conn_id=self.conn_id,
            ancestry=self.ancestry + (str(self.msg.get("id")),),
            cap=_INTERNAL_CAP,
        )
