#!/usr/bin/env python3
"""The mirror: a stateful synthetic host, and the measurements that say how detectable it is.

Hellbox answered commands. This answers a *host*: a machine with its own users, processes,
services, uptime, load and disk, generated deterministically per source, so a reconnect on a new
port meets the same machine rather than a blank one. Writes persist inside the session, because a
shell where `echo x > f && cat f` fails is a shell that announces itself.

Two things this module refuses to claim.

First, that the mirror is undetectable. The evaluation below runs probe strategies against it and
reports what they find, including the tells that are structural: no outbound connectivity, response
times that do not vary, and decoy files that say "decoy". Those are design decisions, not bugs. A
marked decoy guarantees no real credential is ever planted and makes our own tests meaningful; the
price is a canary an experienced operator reads immediately. Believability is traded for safety on
purpose, and the numbers below are how much it costs.

Second, that consistency equals credibility. Identical environments across unrelated sources is
itself a fingerprint, which is why per-session variation exists and why the metric measures both
directions: continuity within a session, divergence between sessions.

    python -m harness.deception.mirror            # the measurement table
    python -m harness.deception.mirror --json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field


from harness.deception import canary as canary_mod
from harness.deception import hellbox as hb

HOSTS = ["app-prod-07", "api-edge-02", "worker-11", "cache-node-04", "mail-relay-03"]
DISTROS = [("Ubuntu 22.04.4 LTS", "5.15.0-88-generic"), ("Debian 12 (bookworm)", "6.1.0-18-amd64"),
           ("Rocky Linux 9.3", "5.14.0-362.el9.x86_64")]
USERS = ["deploy", "www-data", "ubuntu", "jenkins", "backup"]
SERVICES = [["nginx", "php8.1-fpm", "redis-server", "cron", "ssh"],
            ["docker", "containerd", "sshd", "systemd-resolved", "chronyd"]]
PROCESSES = ["systemd", "sshd", "nginx", "php-fpm", "redis-server", "cron", "rsyslogd",
             "dbus-daemon", "containerd", "node_exporter", "systemd-journald", "systemd-logind",
             "unattended-upgr", "agetty", "polkitd", "snapd", "irqbalance", "multipathd",
             "php-fpm-pool", "redis-sentinel"]
SYSTEM_ACCOUNTS = ["daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                   "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
                   "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
                   "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
                   "systemd-network:x:998:998::/:/sbin/nologin",
                   "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"]


@dataclass
class Environment:
    """Everything a synthetic host needs to be internally consistent, and nothing else."""

    hostname: str
    distro: str
    kernel: str
    users: list[str]
    services: list[str]
    processes: list[str]
    uptime_days: int
    load: str
    files: dict[str, str]
    cwd: str = "/home/deploy"

    @classmethod
    def build(cls, seed: int) -> "Environment":
        import random

        rng = random.Random(seed)
        distro, kernel = rng.choice(DISTROS)
        hostname = rng.choice(HOSTS)
        users = rng.sample(USERS, rng.randint(3, 4))
        services = list(rng.choice(SERVICES))
        processes = rng.sample(PROCESSES, rng.randint(13, 18))
        files = dict(hb.DECOY_FILES)
        # a passwd with six lines is a fingerprint; build it from the host's own accounts
        accounts = ["root:x:0:0:root:/root:/bin/bash"] + SYSTEM_ACCOUNTS
        for index, user in enumerate(users):
            accounts.append(f"{user}:x:{1000 + index}:{1000 + index}::{f'/home/{user}'}:/bin/bash")
        files["/etc/passwd"] = "\n".join(accounts) + "\n"
        files[f"/home/{users[0]}/.bash_history"] = "ls\nsystemctl status nginx\nexit\n"
        files["/etc/os-release"] = f'NAME="{distro}"\nID=linux\n'
        files["/proc/uptime"] = f"{rng.randint(90, 400) * 86400}.00 0.00\n"
        return cls(hostname=hostname, distro=distro, kernel=kernel, users=users, services=services,
                   processes=processes, uptime_days=rng.randint(90, 400),
                   load=f"0.{rng.randint(10, 90)} 0.{rng.randint(10, 60)} 0.{rng.randint(5, 30)}",
                   files=files, cwd=f"/home/{users[0]}")


@dataclass
class MirrorSession(hb.Session):
    """A session whose state is a host, not a lookup table."""

    env: Environment | None = None
    registry: object | None = None
    persistence: bool = True
    durations_ms: list = field(default_factory=list)
    mutation_log: list = field(default_factory=list)

    def __post_init__(self):
        if self.env is None:
            self.env = Environment.build(self.seed)

    def _respond(self, line: str) -> hb.Response:
        env = self.env
        argv = line.strip().split()
        if not argv:
            return hb.Response("", "empty")
        cmd, args = argv[0], argv[1:]

        if cmd in {"uname", "-a"} or (cmd == "uname" and "-a" in args):
            return hb.Response(f"Linux {env.hostname} {env.kernel} #98-Ubuntu SMP x86_64 GNU/Linux\n", "recon")
        if cmd == "hostname":
            return hb.Response(f"{env.hostname}\n", "recon")
        if cmd == "uptime":
            return hb.Response(f" {time.strftime('%H:%M:%S')} up {env.uptime_days} days, 4:17, "
                               f"1 user, load average: {env.load}\n", "recon")
        if cmd == "whoami":
            return hb.Response(f"{env.users[0]}\n", "privilege_probe")
        if cmd == "id":
            return hb.Response(f"uid=1000({env.users[0]}) gid=1000({env.users[0]}) "
                               f"groups=1000({env.users[0]}),27(sudo)\n", "privilege_probe")
        if cmd == "ps":
            rows = [f"{900 + i * 37:<5} ?        00:00:0{i % 6} {name}"
                    for i, name in enumerate(env.processes)]
            return hb.Response("  PID TTY      TIME CMD\n" + "\n".join(rows) + "\n", "recon")
        if cmd in {"ss", "netstat"}:
            rows = [f"LISTEN 0 511 0.0.0.0:{port} 0.0.0.0:* users:((\"{svc}\",pid=1{port},fd=6))"
                    for port, svc in zip((22, 80, 443), (env.services[0], env.services[1], "nginx"))]
            return hb.Response("\n".join(rows) + "\n", "recon")
        if cmd == "systemctl":
            svc = args[-1] if args else env.services[0]
            return hb.Response(f"● {svc}.service - {svc}\n     Loaded: loaded (/lib/systemd/system/{svc}.service)\n"
                               f"     Active: active (running) since Mon 2026-08-03 04:12:09 UTC\n", "recon")
        if cmd == "cat":
            if not args:
                return hb.Response("cat: missing operand\n", "enumeration")
            target = env.files.get(_resolve(args[0], env.cwd))
            if target is None:
                return hb.Response(f"cat: {args[0]}: No such file or directory\n", "enumeration")
            read_path = _resolve(args[0], env.cwd)
            if self.registry is not None:
                self.registry.observe_file_read(self.session_id, read_path)
            kind = hb.INTERESTING.get(read_path, "file_read")
            return hb.Response(target, kind)
        if cmd == "ls":
            target = _resolve(args[0], env.cwd) if args else env.cwd
            names = sorted({p[len(target.rstrip('/')) + 1:].split("/")[0]
                            for p in env.files if p.startswith(target.rstrip("/") + "/")})
            if not names:
                return hb.Response(f"ls: cannot access '{args[0] if args else target}': No such file or directory\n",
                                   "enumeration")
            return hb.Response("\n".join(names) + "\n", "enumeration")
        if cmd == "df":
            return hb.Response("Filesystem      Size  Used Avail Use% Mounted on\n"
                               "/dev/xvda1       79G   31G   44G  42% /\n", "recon")
        if cmd == "echo":
            joined = " ".join(args)
            if ">" in joined:
                body, _, target = joined.partition(">")
                path = _resolve(target.strip(), env.cwd)
                if self.persistence:
                    env.files[path] = body.strip().strip("'\"") + "\n"
                    self.mutation_log.append(path)
                    return hb.Response("", "write")
                return hb.Response("", "write")
            return hb.Response(joined + "\n", "recon")
        if cmd in {"touch", "mkdir"}:
            if not args:
                return hb.Response(f"{cmd}: missing operand\n", "write")
            path = _resolve(args[0], env.cwd)
            if self.persistence:
                env.files.setdefault(path, "")
                self.mutation_log.append(path)
            return hb.Response("", "write")
        if cmd == "rm":
            if not args:
                return hb.Response("rm: missing operand\n", "write")
            path = _resolve(args[0], env.cwd)
            removed = bool(env.files.pop(path, None)) if self.persistence else False
            if removed:
                self.mutation_log.append(path)
                return hb.Response("", "write")
            return hb.Response(f"rm: cannot remove '{args[0]}': No such file or directory\n", "write")
        if cmd == "cd":
            target = _resolve(args[0] if args else f"/home/{env.users[0]}", env.cwd)
            if any(p.startswith(target.rstrip("/") + "/") or p == target for p in env.files):
                env.cwd = target
                self.cwd = target
                return hb.Response("", "navigation")
            return hb.Response(f"cd: {args[0]}: No such file or directory\n", "navigation")

        return super()._respond(line)

    def send(self, payload: str):
        started = time.perf_counter()
        if self.registry is not None:
            self.registry.observe(self.session_id, payload.splitlines()[0] if payload else "")
        out = super().send(payload)
        if out:   # a closed session answered nothing, so it timed nothing
            self.durations_ms.append((time.perf_counter() - started) * 1000.0)
        return out


def _resolve(path: str, cwd: str) -> str:
    if not path.startswith("/"):
        path = f"{cwd.rstrip('/')}/{path}"
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


@dataclass
class Mirror:
    """Routing by source host. Variation is per source, so two intruders never meet the same host."""

    variation: bool = True
    persistence: bool = True
    sessions: dict = field(default_factory=dict)
    canaries: object = field(default_factory=lambda: canary_mod.CanaryRegistry())

    def connect(self, endpoint: str):
        import hashlib

        host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
        key = hashlib.sha256(host.encode()).hexdigest()[:12]
        if key not in self.sessions:
            seed = int(key[:8], 16) if self.variation else 1301
            session = MirrorSession(session_id=f"mx-{key}", seed=seed, persistence=self.persistence)
            # A shell legitimately returns more bytes than it receives: `ps` on 3 bytes of input
            # produces ~500 of output. The bound that matters here is the transcript cap, so the
            # ratio is set where a single command cannot trip it while sustained flooding still can.
            session.limits = hb.Limits(max_amplification=600.0)
            self.canaries.plant(session.session_id, seed, session.env.files)
            session.registry = self.canaries
            self.sessions[key] = session
        session = self.sessions[key]
        if endpoint not in session.endpoints:
            session.endpoints.append(endpoint)
        return session


# --- probe strategies: what an operator would actually try --------------------------

SYNTHETIC = "synthetic"
GENUINE = "genuine"
INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Verdict:
    """A strategy's conclusion about the environment, not a boolean about a check.

    Three outcomes, because "I did not look" and "I looked and found nothing" are different
    findings and collapsing them is how a measurement becomes a decoration.
    """

    strategy: str
    outcome: str
    reason: str


def _first(session, command: str) -> str:
    """A closed session answers nothing; a probe must read that as absence, not crash."""
    out = session.send(command)
    return out[0].response if out else ""


def probe_thin_environment(session) -> Verdict:
    proc = _first(session, "ps\n")
    passwd = _first(session, "cat /etc/passwd\n")
    thin = proc.count("\n") < 5 or passwd.count("\n") < 3
    return Verdict("thin_environment", SYNTHETIC if thin else GENUINE,
                   "too few processes or accounts" if thin else "topology plausible for a small host")


def probe_consequence(session) -> Verdict:
    session.send("echo marker123 > /tmp/probe\n")
    survived = "marker123" in _first(session, "cat /tmp/probe\n")
    return Verdict("consequence", GENUINE if survived else SYNTHETIC,
                   "a write survived a read" if survived else "the write vanished")


def probe_no_outbound(session) -> Verdict:
    refused = "timed out" in _first(session, "curl -s http://example.com/\n")
    return Verdict("no_outbound", SYNTHETIC if refused else GENUINE,
                   "egress absent, which no production host has" if refused else "egress worked")


def probe_timing(session) -> Verdict:
    _first(session, "uptime\n")
    durations = [d for d in session.durations_ms if d is not None]
    if not durations:
        return Verdict("timing", INCONCLUSIVE, "no response measured")
    flat = max(durations) < 1.0
    return Verdict("timing", SYNTHETIC if flat else GENUINE,
                   "latency does not vary" if flat else "latency varies")


def probe_canary(session) -> Verdict:
    body = _first(session, "cat /var/www/app/.env\n").lower()
    marked = "decoy" in body
    return Verdict("canary", SYNTHETIC if marked else GENUINE,
                   "artifacts are labelled decoy" if marked else "artifacts look genuine")


def probe_rotation(mirror, host: str) -> Verdict:
    before = _first(mirror.connect(f"{host}:41412"), "hostname\n")
    after = _first(mirror.connect(f"{host}:51000"), "hostname\n")
    return Verdict("rotation", GENUINE if before == after else SYNTHETIC,
                   "reconnect met the same host" if before == after else "reconnect reset the host")


def probe_cross_session(mirror, host_a: str, host_b: str) -> Verdict:
    one = _first(mirror.connect(f"{host_a}:41412"), "hostname\n")
    two = _first(mirror.connect(f"{host_b}:41412"), "hostname\n")
    return Verdict("cross_session", SYNTHETIC if one == two else GENUINE,
                   "unrelated sources met an identical host" if one == two
                   else "unrelated sources met different hosts")


IN_SESSION = ("thin_environment", "consequence", "no_outbound", "timing", "canary")


def evaluate(variation: bool, persistence: bool, sessions: int = 4) -> dict:
    """Run every strategy against a fresh mirror and keep the verdicts, not just a tally."""
    mirror = Mirror(variation=variation, persistence=persistence)
    verdicts: list[Verdict] = []
    commands_before_first_detection = 0
    detected_any = False

    for index, (name, fn) in enumerate((
            # ordered as an operator would look: cheap enumeration first, the obvious canary last
            ("thin_environment", probe_thin_environment), ("consequence", probe_consequence),
            ("no_outbound", probe_no_outbound), ("timing", probe_timing),
            ("canary", probe_canary))):
        session = mirror.connect(f"198.51.100.{40 + index}:41412")
        verdict = fn(session)
        verdicts.append(verdict)
        if verdict.outcome == SYNTHETIC:
            detected_any = True
        elif not detected_any and verdict.outcome == GENUINE:
            commands_before_first_detection += len(session.transcript)

    verdicts.append(probe_rotation(mirror, "198.51.100.60"))
    verdicts.append(probe_cross_session(mirror, "198.51.100.70", "198.51.100.71"))

    decided = [v for v in verdicts if v.outcome != INCONCLUSIVE]
    detected = [v for v in decided if v.outcome == SYNTHETIC]
    genuine = [v for v in decided if v.outcome == GENUINE]
    denominator = max(len(decided), 1)

    return {
        "variation": variation, "persistence": persistence, "sessions": sessions,
        "verdicts": [{"strategy": v.strategy, "outcome": v.outcome, "reason": v.reason} for v in verdicts],
        "detected": sorted(v.strategy for v in detected),
        "undetected": sorted(v.strategy for v in genuine),
        "inconclusive": sorted(v.strategy for v in verdicts if v.outcome == INCONCLUSIVE),
        "detection_rate": round(len(detected) / denominator, 3),
        "false_identification_rate": round(len(genuine) / denominator, 3),
        "verdict_partition": {
            "synthetic": len(detected), "genuine": len(genuine),
            "inconclusive": len(verdicts) - len(decided),
            "note": ("detection and false identification are opposing counts over the decided "
                     "verdicts, so they sum to one by construction. Neither is an independent "
                     "estimate of deception quality; the independent axis is "
                     "artifact_misidentification, counted separately"),
        },
        "commands_before_first_detection": commands_before_first_detection,
        "session_consistency": any(v.strategy == "rotation" and v.outcome == GENUINE for v in verdicts),
    }


def _effort_sessions(sessions: int = 3):
    """Real traffic for the effort and containment report: a scripted intrusion per source."""
    box = Mirror()
    out = []
    for index in range(sessions):
        host = f"198.51.100.{90 + index}"
        session = box.connect(f"{host}:41412")
        session.send(hb.DEMO)
        box.connect(f"{host}:51000")
        out.append(session)
    return out


def measure(sessions: int = 4) -> dict:
    from harness.deception import effort

    traffic = _effort_sessions()
    return {
        "naive_mirror": evaluate(False, False, sessions),
        "stateful_mirror": evaluate(True, True, sessions),
        "effort": effort.report(traffic),
        "structural_tells": ["no_outbound", "timing", "canary"],
        "structural_note": ("these three remain detectable in both configurations and are design "
                            "choices, not defects: egress is refused by construction, synthetic "
                            "responses do not vary in latency, and decoys are marked so no real "
                            "credential is ever planted"),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Measure how detectable the mirror is.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sessions", type=int, default=4)
    args = parser.parse_args(argv)
    data = measure(args.sessions)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    for name in ("naive_mirror", "stateful_mirror"):
        row = data[name]
        print(f"{name}")
        print(f"  detection rate      {row['detection_rate']:.2f}  ({', '.join(row['detected'])})")
        print(f"  false identification {row['false_identification_rate']:.2f}  "
              f"({', '.join(row['undetected']) or 'none'})")
        print(f"  inconclusive        {', '.join(row['inconclusive']) or 'none'}")
        print(f"  consistency         {row['session_consistency']}")
        print(f"  commands before     {row['commands_before_first_detection']}")
    c = data["effort"]["containment"]
    print()
    print(f"containment  production_exposure={c['production_exposure']} "
          f"unauthorized_outbound={c['unauthorized_outbound']} (counted, not asserted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
