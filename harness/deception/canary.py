"""An active canary: the token is the trap, and using it is the alarm.

Two properties, kept apart on purpose.

Reproducible: with no secret, the token is derived from the session seed and id, so a test can
assert on it. Reproducible is not unguessable. Anyone holding this source can compute the same
token from a known seed, so a deterministic token is a fixture, not a credential, and every record
says which kind it is.

Unguessable: pass a secret and the token becomes HMAC-SHA256(secret, seed || session). The secret
is never stored in this repository, and `secret_backed` records that the property was requested
rather than assumed.

The canary cannot leave the machine. It records touches, raises priority, and links sessions that
share a token. It does not resolve the holder, and a shared token is not evidence of one operator.
"""

from __future__ import annotations

import hashlib
import hmac

PLANT_PATHS = ("/var/www/app/.env", "/home/deploy/.aws/credentials")
MARKER = "# deploy credentials, rotated 2026-04-11"


def derive_token(seed: int, session_id: str, secret: bytes | None = None) -> str:
    """A token for this session. Deterministic without a secret, keyed with one."""
    material = f"{seed}:{session_id}".encode()
    if secret is not None:
        return hmac.new(secret, material, hashlib.sha256).hexdigest()[:24]
    return hashlib.sha256(material).hexdigest()[:24]


class Canary:
    def __init__(self, session_id: str, seed: int, secret: bytes | None = None):
        self.session_id = session_id
        self.token = derive_token(seed, session_id, secret)
        self.secret_backed = secret is not None
        self.planted_at: list[str] = []
        self.touches: list[dict] = []

    def touch(self, where: str, evidence: str, seen_in: str | None = None) -> dict:
        record = {"session_id": self.session_id, "seen_in": seen_in or self.session_id,
                  "where": where, "evidence": evidence}
        self.touches.append(record)
        return record

    def record(self) -> dict:
        return {"session_id": self.session_id, "token_suffix": self.token[-6:],
                "secret_backed": self.secret_backed, "planted_at": list(self.planted_at),
                "touches": len(self.touches), "predictable": not self.secret_backed}


class CanaryRegistry:
    """Session-scoped lookups for file reads, token-global lookups for reuse.

    Keyed by session id rather than by token: with `variation=False` every session shares a seed,
    and a token-keyed registry silently overwrote earlier sessions.
    """

    def __init__(self) -> None:
        self.by_session: dict[str, Canary] = {}
        self.by_token: dict[str, Canary] = {}

    def plant(self, session_id: str, seed: int, files: dict, secret: bytes | None = None) -> Canary:
        canary = Canary(session_id, seed, secret)
        for path in PLANT_PATHS:
            existing = files.get(path, "")
            if canary.token in existing:
                canary.planted_at.append(path)
                continue
            body = existing if existing.endswith("\n") or not existing else existing + "\n"
            files[path] = f"{body}{MARKER}\nAWS_ACCESS_KEY_ID={canary.token}\n"
            canary.planted_at.append(path)
        self.by_session[session_id] = canary
        self.by_token[canary.token] = canary
        return canary

    def observe(self, session_id: str, text: str) -> dict | None:
        """A token appearing in a command. Global: a foreign token is the reuse signal."""
        for token, canary in self.by_token.items():
            if token in text:
                owner = "own" if canary.session_id == session_id else "foreign"
                return canary.touch(f"command:{owner}", f"token seen from {session_id}",
                                    seen_in=session_id)
        return None

    def observe_file_read(self, session_id: str, path: str) -> dict | None:
        """A planted path opened in this session. Scoped: B reading .env cannot fire A."""
        canary = self.by_session.get(session_id)
        if canary is None or path not in canary.planted_at:
            return None
        return canary.touch("file_read", path)

    def links(self) -> list[dict]:
        seen: dict[str, set[str]] = {}
        for session_id, canary in self.by_session.items():
            if not canary.touches:
                continue
            sessions = {session_id} | {t["seen_in"] for t in canary.touches}
            seen.setdefault(canary.token, set()).update(sessions)
        return [{"token_suffix": token[-6:], "sessions": sorted(ids),
                 "identity_claim": "not established",
                 "note": "a shared token links observations, not people"}
                for token, ids in seen.items() if len(ids) > 1]

    def report(self) -> dict:
        return {"sessions": len(self.by_session),
                "predictable_tokens": sum(1 for c in self.by_session.values() if not c.secret_backed),
                "touches": sum(len(c.touches) for c in self.by_session.values()),
                "priority_high": [s for s, c in self.by_session.items() if c.touches],
                "links": self.links(),
                "unguessability": "not established for deterministic tokens; supply a secret"}


def demo() -> CanaryRegistry:
    registry = CanaryRegistry()
    alpha, beta = {}, {}
    registry.plant("mx-alpha", 1301, alpha)
    registry.plant("mx-beta", 1301, beta)
    registry.observe_file_read("mx-alpha", "/var/www/app/.env")
    registry.observe("mx-beta", f"export AWS_ACCESS_KEY_ID={registry.by_session['mx-alpha'].token}")
    return registry


def main(argv: list[str] | None = None) -> int:
    report = demo().report()
    print(f"planted in {report['sessions']} sessions, {report['touches']} touch(es)")
    for link in report["links"]:
        print(f"link: {link['sessions'][0]} -> also seen in {link['sessions'][1]} "
              f"(identity: {link['identity_claim']})")
    for session in report["priority_high"]:
        print(f"priority high: {session}")
    print(f"unguessability: {report['unguessability']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
