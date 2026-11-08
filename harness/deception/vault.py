"""An in-memory filesystem. It has no directory on any disk, which is the point.

`read` resolves a path against the fake root and refuses anything that would leave it.
The naive version this replaces used `os.path.join` and handed back whatever the peer
asked for; the difference is one normalization call and an explicit boundary check.
"""
from __future__ import annotations

import posixpath

from . import Issuance
from . import watermark


class EscapedRoot(Exception):
    """A peer asked for something outside the fabricated tree."""


class FakeTree:
    def __init__(self, issuance: Issuance) -> None:
        self.issuance = issuance
        self.files: dict[str, str] = {}
        self.access_log: list[dict] = []
        self._seed()

    def _seed(self) -> None:
        """Plausible contents. No host paths, no real usernames, no real keys."""
        self.files = {
            "/home/svc-deploy/.aws/credentials": (
                "[default]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\n"
            ).format(key="PLACEHOLDER", secret="PLACEHOLDER"),
            "/home/svc-deploy/notes/deploy-checklist.md": (
                "# Deploy checklist\n\n- rotate staging keys\n- check the ops runbook link\n- confirm backup job\n"
            ),
            "/srv/app/.env": (
                "DB_HOST=10.42.0.11\nDB_USER=app\nDB_PASSWORD={pw}\nSENTRY_DSN=\n"
            ).format(pw="PLACEHOLDER"),
            "/srv/app/README.internal.md": (
                "# app\n\nInternal notes. Access requests go through the ops queue, not the shared inbox.\n"
            ),
        }

    def _normalize(self, path: str) -> str:
        """Refuse traversal outright rather than normalizing it away.

        The tree is in memory, so no path can reach a real file. Refusing is still the
        right answer: silently resolving `/../../etc/passwd` to `/etc/passwd` inside the
        fake root would hide the attempt from the access log.
        """
        if ".." in path.split("/"):
            self.access_log.append({"path": path, "event": "escape", "purpose": "peer"})
            raise EscapedRoot(path)
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path)

    def read(self, path: str, purpose: str = "read") -> str:
        norm = self._normalize(path)
        if norm not in self.files:
            self.access_log.append({"path": norm, "event": "miss", "purpose": purpose})
            raise FileNotFoundError(norm)
        body = self.files[norm].replace("PLACEHOLDER", self.issuance.fingerprint("vault_file", 20))
        self.access_log.append({"path": norm, "event": "read", "purpose": purpose})
        return watermark.apply(body, self.issuance)

    def write(self, path: str, body: str) -> str:
        norm = self._normalize(path)
        self.files[norm] = body
        self.access_log.append({"path": norm, "event": "write", "purpose": "peer"})
        return norm

    def listing(self, path: str = "/") -> list[str]:
        norm = self._normalize(path.rstrip("/") or "/")
        prefix = norm if norm.endswith("/") else norm + "/"
        return sorted(p for p in self.files if p.startswith(prefix))

    def reads(self) -> list[dict]:
        return [e for e in self.access_log if e["event"] in ("read", "miss")]
