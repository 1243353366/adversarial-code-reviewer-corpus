#!/usr/bin/env python3
"""What the deception actually cost the attacker, and what it actually bought the defender.

These are two different numbers and conflating them is how honeypot reporting turns into
storytelling. Dwell time is a proxy for attacker effort: it is measurable, it is not money, and a
patient operator can spend an hour costing the defender more than himself. Defensive benefit is
measured separately: sessions absorbed away from production, decoys that consumed attention, and
the two invariants that must be zero and are counted rather than asserted.

The zero targets are the part this module exists for. `production_exposure` and
`unauthorized_outbound` are computed by scanning the deception package's own source for capabilities
that could reach a host or a network. A hardcoded zero is a decoration; an audit that can return
non-zero is a measurement, and the test suite plants a violating module to prove this one can.

    python harness/deception/effort.py            # the report
    python harness/deception/effort.py --json
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent

# Capabilities that would let the sinkhole reach something outside itself.
EGRESS_CAPABLE = {"socket", "ssl", "urllib", "http", "requests", "httpx", "telnetlib", "ftplib",
                  "smtplib", "paramiko", "subprocess", "asyncio", "select"}
HOST_REACHING = EGRESS_CAPABLE | {"os", "shutil", "glob", "tempfile"}

DECOY_CLASSES = {"credential_file", "secret_file", "private_key_attempt", "source_disclosure"}
RECON_CLASSES = {"recon", "enumeration", "privilege_probe"}


def audit_module(path: Path) -> dict:
    """What this module could do to the world, read from its imports and its call sites."""
    tree = ast.parse(path.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    egress = sorted(imported & EGRESS_CAPABLE)
    reaching = sorted(imported & HOST_REACHING)

    # A builtin open() is a real-filesystem read regardless of which import preceded it.
    builtin_opens = [n.lineno for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"]
    return {"module": path.name, "imported": sorted(imported), "egress_capable": egress,
            "host_reaching": reaching, "builtin_open_calls": builtin_opens}


def audit_package(directory: Path = PACKAGE, exclude: tuple[str, ...] = ("effort.py",)) -> dict:
    """The zero targets, counted. exclude: this module imports nothing dangerous either, but it
    reports on the package rather than participating in it."""
    modules = [p for p in sorted(directory.glob("*.py")) if p.name not in exclude]
    audits = [audit_module(p) for p in modules]
    violations = [a for a in audits if a["egress_capable"] or a["builtin_open_calls"]]
    return {
        "modules_audited": [a["module"] for a in audits],
        "production_exposure": sum(len(a["host_reaching"]) for a in audits),
        "unauthorized_outbound": sum(len(a["egress_capable"]) for a in audits),
        "unexplained_file_access": sum(len(a["builtin_open_calls"]) for a in audits),
        "violating_modules": [a["module"] for a in violations],
        "method": ("static: imports plus builtin open() call sites, per module; a module that "
                   "acquires egress capability makes the zero target fail rather than being "
                   "assumed away"),
    }


def attacker_effort(sessions) -> dict:
    """Dwell and interaction counts from real sessions. Inferences are labelled as inferences."""
    dwell = 0.0
    commands = 0
    decoy_hits = 0
    recon_by_command: dict[str, int] = {}
    repeated_recon = 0
    absorbed = 0

    for session in sessions:
        dwell += session.elapsed
        commands += len(session.transcript)
        absorbed += 1
        for entry in session.transcript:
            if entry.classified_as in DECOY_CLASSES:
                decoy_hits += 1
            if entry.classified_as in RECON_CLASSES:
                key = entry.request.strip().split()[0] if entry.request.strip() else ""
                recon_by_command[key] = recon_by_command.get(key, 0) + 1

    for count in recon_by_command.values():
        if count > 1:
            repeated_recon += count - 1

    return {
        "measured": {
            "time_in_deception_seconds": round(dwell, 3),
            "commands_answered": commands,
            "repeated_reconnaissance_attempts": repeated_recon,
            "decoy_interactions": decoy_hits,
            "sessions_absorbed": absorbed,
        },
        "inferred": {
            "attacker_effort_low_minutes": round(dwell / 60.0, 2),
            "basis": "dwell time as a floor on operator attention, not a cost",
            "caveat": ("time spent in a honeypot is not money lost. A patient operator can spend an "
                       "hour here at no cost to himself, so this number bounds effort, not damage"),
        },
    }


def artifact_misidentification(sessions) -> dict:
    """The axis that is not a partition: did a decoy pass as a real artifact?

    Environment-level detection and environment-level false identification sum to one by
    construction, which makes presenting them as two findings misleading. This one stands alone: a
    decoy is misidentified when its content carries no marker of its own, so a single unmarked decoy
    makes the count non-zero. Our decoys are all marked, which is why the number is zero and why the
    test that plants one is the thing that proves the count works.
    """
    served = 0
    misidentified = 0
    examples: list[str] = []
    for session in sessions:
        for entry in session.transcript:
            if entry.classified_as not in DECOY_CLASSES:
                continue
            served += 1
            if "decoy" not in entry.response.lower():
                misidentified += 1
                examples.append(f"{session.session_id}:{entry.request.strip()[:40]}")
    return {
        "decoy_artifacts_served": served,
        "misidentified_as_genuine": misidentified,
        "examples": examples[:5],
        "method": "counted from served decoys whose content carries no marker, not inferred",
    }


def defensive_benefit(sessions, containment: dict) -> dict:
    """What the defender can show. Separate from what the attacker may have lost."""
    return {
        "measured": {
            "sessions_kept_off_production": len(sessions),
            "production_exposure": containment["production_exposure"],
            "unauthorized_outbound": containment["unauthorized_outbound"],
            "unexplained_file_access": containment["unexplained_file_access"],
            "evidence_records_produced": len(sessions),
        },
        "zero_targets": ["production_exposure", "unauthorized_outbound", "unexplained_file_access"],
        "note": ("zero targets are counted by audit_package, not asserted by the caller; a module "
                 "that acquires egress capability reports a non-zero value"),
    }


def report(sessions) -> dict:
    containment = audit_package()
    return {
        "containment": containment,
        "artifact_integrity": artifact_misidentification(sessions),
        "attacker_effort": attacker_effort(sessions),
        "defensive_benefit": defensive_benefit(sessions, containment),
        "design_principle": ("make unauthorized access unproductive, reconnaissance expensive in "
                             "time, repeated behaviour observable, and the defender's own "
                             "infrastructure cheaper to protect than the attacker's effort"),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Attacker effort versus defensive benefit.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    from harness.deception import hellbox as hb
    from harness.deception import mirror as mx

    box = mx.Mirror()
    sessions = []
    for host in ("198.51.100.90", "198.51.100.91", "198.51.100.92"):
        session = box.connect(f"{host}:41412")
        session.send(hb.DEMO)
        box.connect(f"{host}:51000")
        sessions.append(session)

    data = report(sessions)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    c = data["containment"]
    print(f"modules audited            {', '.join(c['modules_audited'])}")
    print(f"production exposure       {c['production_exposure']}   (target 0, counted)")
    print(f"unauthorized outbound     {c['unauthorized_outbound']}   (target 0, counted)")
    print(f"unexplained file access   {c['unexplained_file_access']}")
    print()
    for label in ("measured",):
        for key, value in data["attacker_effort"][label].items():
            print(f"  effort   {key:<34}{value}")
    for key, value in data["defensive_benefit"]["measured"].items():
        print(f"  benefit  {key:<34}{value}")
    artifact = data["artifact_integrity"]
    print(f"  axis     decoys served {artifact['decoy_artifacts_served']}  "
          f"misidentified {artifact['misidentified_as_genuine']}  (independent of the partition)")
    print()
    print(f"  caveat   {data['attacker_effort']['inferred']['caveat']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
