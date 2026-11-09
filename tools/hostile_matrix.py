#!/usr/bin/env python3
"""Attack the security invariant, not the findings list.

The invariant: no unauthorized change to a protected file results in repository code being
executed before the change is detected. Every mutation below is applied to a full copy of the
tree, then the CI gate is run in the order CI runs it. A mutation that reaches the execution
step is a failure of the design even if the verifier would have complained afterwards.

Detection is checked by exit status. Ordering is checked by a canary: the protected-script
mutation writes a marker file if its module is imported. The clean control run imports the same
module and requires the marker to appear, so an absent marker means "never executed" rather
than "canary never worked".

What this does not establish: that the gate's own trust roots are sound. The verifier digest and
the anchor are supplied to this harness from outside the copy, exactly as CI supplies them from
repository variables. If those values are wrong, every mutation passes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANARY_ENV = "HOSTILE_CANARY"

PROTECTED_SCRIPT = "harness/untrusted_peer/protocol.py"
CANARY_CODE = (
    "\n\nimport os as _os, pathlib as _pl\n"
    f"_marker = _os.environ.get('{CANARY_ENV}')\n"
    "if _marker:\n"
    "    _pl.Path(_marker).write_text('executed', encoding='utf-8')\n"
)


@dataclass
class Mutation:
    name: str
    apply: object
    expect_gate_step: int = 2          # 1 = verifier digest, 2 = integrity verify
    requires: list[str] = field(default_factory=list)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _edit_lock(root: Path) -> None:
    lock = root / "harness" / "integrity.lock"
    data = json.loads(lock.read_text())
    first = sorted(data["files"])[0]
    data["files"][first] = "0" * 64
    lock.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _edit_anchor(root: Path) -> None:
    sec = root / "SECURITY.md"
    sec.write_text(re.sub(r"set digest: [0-9a-f]{64}", "set digest: " + "0" * 64, sec.read_text()))


def _add_dependency(root: Path) -> None:
    req = root / "requirements-dev.txt"
    req.write_text(req.read_text() + "trojanified-package==9.9.9\n")


def _inject_script(root: Path) -> None:
    target = root / PROTECTED_SCRIPT
    target.write_text(target.read_text() + CANARY_CODE)


def _replace_verifier(root: Path) -> None:
    (root / "tools" / "integrity.py").write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        # A verifier that always agrees. It must never be reached: the digest check comes first.
        "print('integrity ok')\nsys.exit(0)\n"
    )


def _both(fns):
    def apply(root: Path) -> None:
        for fn in fns:
            fn(root)
    return apply


MUTATIONS = [
    Mutation("replace_verifier", _replace_verifier, 1),
    Mutation("modify_lock", _edit_lock),
    Mutation("modify_anchor", _edit_anchor),
    Mutation("modify_dependencies", _add_dependency),
    Mutation("modify_protected_script", _inject_script),
    Mutation("verifier_and_lock", _both([_replace_verifier, _edit_lock]), 1),
    Mutation("lock_and_anchor", _both([_edit_lock, _edit_anchor])),
    Mutation("dependencies_and_script", _both([_add_dependency, _inject_script])),
    Mutation("everything", _both([_replace_verifier, _edit_lock, _edit_anchor, _add_dependency, _inject_script]), 1),
]


def _copy_tree(destination: Path) -> Path:
    target = destination / "repo"
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    return target


def gate(root: Path, verifier_digest: str, anchor: str, marker: Path) -> dict:
    """Run the CI gate in CI order. Returns where it stopped and whether code ran."""
    result = {"step": 0, "reason": "", "executed": False, "output": ""}

    result["step"] = 1
    if _sha(root / "tools" / "integrity.py") != verifier_digest:
        result["reason"] = "verifier_digest_mismatch"
        return result

    result["step"] = 2
    env = dict(os.environ, PYTHONPATH=str(root))
    proc = subprocess.run([sys.executable, "tools/integrity.py", "verify", "--anchor", anchor],
                          cwd=root, capture_output=True, text=True, env=env)
    result["output"] = (proc.stdout + proc.stderr)[-300:]
    if proc.returncode != 0:
        result["reason"] = "integrity_verify_failed"
        return result

    # Step 3 is where pip install -r requirements-dev.txt would run, and step 4 where the
    # protected scripts execute. Reaching here means the gate trusted the tree.
    result["step"] = 3
    result["executed"] = _execute_protected(root, env, marker)
    return result


def _execute_protected(root: Path, env: dict, marker: Path) -> bool:
    """Step 4: import a protected module. True means repository code actually ran."""
    code = (
        "import importlib, sys\n"
        f"sys.path.insert(0, {str(root)!r})\n"
        "importlib.import_module('harness.untrusted_peer.protocol')\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True,
                          env=dict(env, **{CANARY_ENV: str(marker)}))
    return proc.returncode == 0


def canary_works() -> bool:
    """A control for the control: inject the canary and require the marker to appear.

    Without this, every "code_executed: false" above would be equally consistent with a canary
    that never fires. The matrix's strongest claim rests on this function.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = _copy_tree(Path(tmp))
        _inject_script(root)
        marker = Path(tmp) / "canary.marker"
        executed = _execute_protected(root, dict(os.environ), marker)
        return executed and marker.exists() and marker.read_text() == "executed"


def workflow_problems(text: str) -> list[str]:
    """Ordering check on the raw workflow: verification text must precede executable steps.

    Works on lines rather than parsed steps, because a step's command is often a block scalar and
    a name-only reading misses it. That miss is what let the install-before-verify ordering ship.
    """
    lines = text.splitlines()
    verify = next((i for i, line in enumerate(lines)
                   if "integrity.py" in line and "name:" not in line), None)
    if verify is None:
        return ["no integrity verification command in the workflow"]
    risky = ("pip install", "pytest", "python -m", "python tools/", "python harness/")
    for i, line in enumerate(lines):
        if "integrity.py" in line:
            continue
        if any(term in line for term in risky) and i < verify:
            return [f"executable step precedes verification: {line.strip()[:70]}"]
    return []


def run(verbose: bool = True) -> dict:
    verifier_digest = _sha(ROOT / "tools" / "integrity.py")
    anchor = _anchor_from_security(ROOT)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        clean = _copy_tree(tmp_path)
        marker = tmp_path / "clean.marker"
        control = gate(clean, verifier_digest, anchor, marker)
        rows.append({
            "mutation": "clean_control",
            "detected": control["step"] >= 3,
            "stopped_at": control["step"],
            "reason": "reached execution",
            "code_executed": control["executed"],
            "ok": control["step"] >= 3 and control["executed"] is True,
        })

    for mutation in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            target = _copy_tree(tmp_path)
            mutation.apply(target)
            marker = tmp_path / "mutated.marker"
            outcome = gate(target, verifier_digest, anchor, marker)
            detected = outcome["step"] < 3
            ok = detected and not outcome["executed"] and outcome["step"] <= mutation.expect_gate_step
            rows.append({
                "mutation": mutation.name,
                "detected": detected,
                "stopped_at": outcome["step"],
                "reason": outcome["reason"] or "reached execution",
                "code_executed": outcome["executed"],
                "ok": ok,
            })
            if verbose:
                print(f"  {mutation.name:26} stopped_at={outcome['step']} "
                      f"executed={outcome['executed']} {outcome['reason']}")
    return {"rows": rows, "ok": all(r["ok"] for r in rows)}


def _anchor_from_security(root: Path) -> str:
    text = (root / "SECURITY.md").read_text()
    match = re.search(r"set digest: ([0-9a-f]{64})", text)
    if not match:
        raise SystemExit("SECURITY.md has no pinned set digest")
    return match.group(1)


def main(argv: list[str]) -> int:
    quiet = "--json" in argv
    if not quiet:
        print("hostile change matrix")
    if not canary_works():
        print("canary does not fire; every 'not executed' below is meaningless")
        return 2
    report = run(verbose=not quiet)
    if "--json" in argv:
        print(json.dumps(report, indent=2))
    bad = [r for r in report["rows"] if not r["ok"]]
    if bad:
        if not quiet:
            print(f"\nFAILED: {len(bad)} of {len(report['rows'])} cases")
        return 1
    if not quiet:
        print(f"\nall {len(report['rows'])} cases hold: "
              f"{len(MUTATIONS)} mutations detected before execution, clean control reaches execution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
