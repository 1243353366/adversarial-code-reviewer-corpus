"""The anti-pattern, kept deliberately and only as a fixture.

Every function here is a real failure mode seen in handlers that trust the peer:
the declared length is allocated, the payload is parsed without a type check, the
peer's own claims about its role are believed, and its text goes straight to a log.

It executes nothing. It is here so the tests can show each defect reproducing before
showing the hardened version refusing it.
"""
from __future__ import annotations

import json
import struct


class NaiveListener:
    def __init__(self, log=print):
        self.log = log
        self.accepted = 0

    def read_one(self, peer) -> dict:
        header = peer.read_exact(4)
        (declared,) = struct.unpack(">I", header)
        # The defect: the peer chooses the allocation size.
        body = peer.read_exact(declared)
        msg = json.loads(body.decode("utf-8"))
        # The defect: whatever role the peer asserts is what the listener believes.
        self.accepted += 1
        self.log(f"peer[{msg.get('role', 'peer')}] said: {msg.get('note', '')}")
        return msg
