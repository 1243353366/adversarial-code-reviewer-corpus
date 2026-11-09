"""An active canary: the token is the trap, and using it is the alarm.

A passive canary waits in a file to be noticed. This one is a bearer token, planted per session,
that does work the moment it is touched: it records what touched it and where, links sessions that
used the same token, and raises the session's priority. Reuse is the interesting event, because a
credential pasted into a different session or a different infrastructure is the one observation
that ties two attempts to one operator.

Three things this deliberately does not do, because they would convert a defensive system into a
different category of thing: it does not call back to any collector, it does not follow the token
to whoever is holding it, and it never leaves the process. Everything it produces is a local
record. Containment is the feature; a beacon with an IP address in it is an offence with a logfile.

Tokens are unguessable but not random at test time: derived from the session seed so a run is
reproducible, which is what makes the reuse tests meaningful.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def derive_token(seed: int) -> str:
    """Decoy-shaped, deterministic per seed, and useless outside this process."""
    body = hashlib.sha256(f"canary:{seed}".encode()).hexdigest().upper()
    return "AKIA" + body[:16]


@dataclass
class Touch:
    token: str
    session_id: str
    where: str          # "command" | "file_read"
    evidence: str       # the command or path, truncated


@dataclass
class Canary:
    token: str
    session_id: str
    planted_at: list[str] = field(default_factory=list)
    touches: list[Touch] = field(default_factory=list)
    priority: str = "normal"

    def touch(self, session_id: str, where: str, evidence: str) -> Touch:
        hit = Touch(self.token, session_id, where, evidence[:120])
        self.touches.append(hit)
        if session_id != self.session_id or where == "file_read":
            self.priority = "high"
        return hit

    def as_record(self) -> dict:
        return {
            "token_suffix": self.token[-6:],   # never the whole token in a report
            "planted_at": self.planted_at,
            "touches": len(self.touches),
            "sessions": sorted({t.session_id for t in self.touches}),
            "reused_outside_planting_session": any(
                t.session_id != self.session_id for t in self.touches),
            "priority": self.priority,
            "method": ("touches are local records; nothing is transmitted and no holder is "
                       "contacted"),
        }


class CanaryRegistry:
    """Planted tokens and what happened to them. One registry per deployment."""

    PLANT_PATHS = ("/var/www/app/.env", "/home/deploy/.aws/credentials")

    def __init__(self) -> None:
        self.canaries: dict[str, Canary] = {}

    def plant(self, session_id: str, seed: int, env) -> Canary:
        """Write the token into synthetic files the session serves, and keep the reference."""
        canary = Canary(token=derive_token(seed), session_id=session_id)
        for path in self.PLANT_PATHS:
            if hasattr(env, "files"):
                env.files[path] = (f"AWS_ACCESS_KEY_ID={canary.token}\n"
                                   f"AWS_SECRET_ACCESS_KEY=canary-{seed}\n")
                canary.planted_at.append(path)
        self.canaries[canary.token] = canary
        return canary

    def resolve(self, text: str) -> Canary | None:
        """Which canary, if any, appears in this text."""
        for token, canary in self.canaries.items():
            if token in text:
                return canary
        return None

    def observe(self, session_id: str, text: str, where: str = "command") -> Touch | None:
        canary = self.resolve(text)
        if canary is None:
            return None
        return canary.touch(session_id, where, text)

    def observe_file_read(self, session_id: str, path: str) -> Touch | None:
        """The alarm that matters: a planted path was actually opened, not merely listed."""
        for canary in self.canaries.values():
            if path in canary.planted_at:
                return canary.touch(session_id, "file_read", path)
        return None

    def links(self) -> list[dict]:
        """Session pairs tied together by a shared token: the attribution product."""
        out = []
        for canary in self.canaries.values():
            sessions = sorted({t.session_id for t in canary.touches})
            for other in sessions:
                if other != canary.session_id:
                    out.append({"planted_in": canary.session_id, "also_seen_in": other,
                                "token_suffix": canary.token[-6:]})
        return out

    def report(self) -> dict:
        touched = [c for c in self.canaries.values() if c.touches]
        return {
            "tokens_planted": len(self.canaries),
            "tokens_touched": len(touched),
            "touches": sum(len(c.touches) for c in self.canaries.values()),
            "priority": "high" if any(c.priority == "high" for c in self.canaries.values()) else "normal",
            "links": self.links(),
            "canaries": [c.as_record() for c in self.canaries.values()],
        }


def main(argv: list[str] | None = None) -> int:
    class _Env:
        files: dict[str, str] = {}

    registry = CanaryRegistry()
    planted = registry.plant("mx-alpha", 1301, _Env)
    registry.observe_file_read("mx-alpha", "/var/www/app/.env")
    registry.observe("mx-beta", f"export AWS_ACCESS_KEY_ID={planted.token}")
    print(f"planted {len(planted.planted_at)} paths, token ...{planted.token[-6:]}")
    for pair in registry.links():
        print(f"link: planted in {pair['planted_in']} -> also seen in {pair['also_seen_in']}")
    print(f"priority {registry.report()['priority']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
