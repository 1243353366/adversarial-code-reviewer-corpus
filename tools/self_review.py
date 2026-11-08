#!/usr/bin/env python3
"""A reviewer that reads this repository's own code, using the rules it keeps writing down.

Every rule here is a defect class the corpus already catalogued from someone else's work,
applied back to the modules that do the cataloguing. Findings are reported with file, line,
rule and one sentence on why it matters.

    python tools/self_review.py            # human table, exit 1 on any high severity
    python tools/self_review.py --list     # rules only

Deliberate anti-pattern fixtures (harness/*/naive.py) are exempt only through an allowlist
entry that carries a written reason. An exemption without a reason is a suppression.
"""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [ROOT / "harness", ROOT / "tools"]
ALLOWLIST = ROOT / "harness" / "self_review_allow.txt"
PEER_AUTH_KEYS = {"role", "origin", "cmd", "admin", "scope", "authenticated"}
PAYLOAD_NAMES = {"msg", "payload", "body", "message", "data", "envelope", "frame"}

HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    why: str

    def render(self) -> str:
        return f"{self.path}:{self.line}  {self.severity:6} {self.rule:28} {self.why}"


def _names_from(module: ast.AST, pattern: str) -> set[str]:
    """Local variables assigned from a call whose dotted name ends with `pattern`."""
    out: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            dotted = getattr(func, "attr", getattr(func, "id", ""))
            if dotted == pattern:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        out.add(tgt.id)
                    elif isinstance(tgt, ast.Tuple):
                        out.update(e.id for e in tgt.elts if isinstance(e, ast.Name))
    return out


def rule_peer_authority(tree: ast.AST, path: str) -> list[Finding]:
    """Authorization decided from a field the peer wrote."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id not in PAYLOAD_NAMES:
                continue
            key = node.slice
            name = getattr(key, "value", None) if isinstance(key, ast.Constant) else None
            if isinstance(name, str) and name in PEER_AUTH_KEYS:
                out.append(Finding(path, node.lineno, "peer_authority_from_payload", HIGH,
                                   f"'{name}' read from a peer-supplied mapping decides trust"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr != "get" or not isinstance(node.func.value, ast.Name):
                continue
            if node.func.value.id not in PAYLOAD_NAMES or not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and arg.value in PEER_AUTH_KEYS:
                out.append(Finding(path, node.lineno, "peer_authority_from_payload", HIGH,
                                   f"'{arg.value}' read from a peer-supplied mapping decides trust"))
    return out


def rule_length_before_bound(tree: ast.AST, path: str) -> list[Finding]:
    """A length taken from the peer used as an allocation or read size."""
    unpacked = _names_from(tree, "unpack")
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = getattr(func, "attr", getattr(func, "id", ""))
        if name not in {"read_exact", "recv", "allocate", "bytearray"}:
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Name) and arg.id in unpacked:
            out.append(Finding(path, node.lineno, "peer_length_before_bound", HIGH,
                               f"'{arg.id}' came from the wire and is used as a size unbounded"))
    return out


def rule_deque_without_maxlen(tree: ast.AST, path: str) -> list[Finding]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "deque":
            if not any(kw.arg == "maxlen" for kw in node.keywords):
                out.append(Finding(path, node.lineno, "unbounded_queue", MEDIUM,
                                   "queue has no maxlen, so growth is the peer's choice"))
    return out


def rule_mutable_default(tree: ast.AST, path: str) -> list[Finding]:
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                out.append(Finding(path, node.lineno, "mutable_default", MEDIUM,
                                   "mutable default shared across calls"))
    return out


def rule_bare_except(tree: ast.AST, path: str) -> list[Finding]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            out.append(Finding(path, node.lineno, "bare_except", MEDIUM,
                               "catches everything, including the exit signal"))
    return out


def rule_string_identity(tree: ast.AST, path: str) -> list[Finding]:
    """Provenance or capability compared against a string literal."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        left, right = node.left, node.comparators[0]
        for a, b in ((left, right), (right, left)):
            label = getattr(a, "id", None) or getattr(a, "attr", None) or ""
            if isinstance(b, ast.Constant) and isinstance(b.value, str):
                if label in {"origin", "cap", "capability", "role"}:
                    out.append(Finding(path, node.lineno, "string_identity_compare", HIGH,
                                       f"{label} compared to a literal, so any writer can spell it"))
    return out


def _floored_names(tree: ast.AST) -> set[str]:
    """Names bound to max(...), which is how this codebase floors a denominator."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if getattr(node.value.func, "id", "") == "max":
                out.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return out


def rule_ratio_without_floor(tree: ast.AST, path: str) -> list[Finding]:
    """A ratio whose denominator is peer-supplied can be zero, and 0/0 is not a small number."""
    out = []
    if not path.startswith("harness/"):
        return out  # authoring scripts do arithmetic over their own lists, not over peer input
    floored = _floored_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
            continue
        denom = node.right
        guarded = isinstance(denom, ast.Call) and getattr(denom.func, "id", "") == "max"
        if isinstance(denom, ast.Name) and denom.id in floored:
            guarded = True
        if not guarded and isinstance(denom, (ast.Name, ast.Attribute)):
            out.append(Finding(path, node.lineno, "ratio_without_floor", HIGH,
                               "denominator is unguarded, so an empty request yields NaN"))
    return out


def rule_policy_scatter(tree: ast.AST, path: str) -> list[Finding]:
    """Thresholds declared per module are policy that nobody can inspect in one place."""
    out = []
    if not path.startswith("harness/") or path.endswith("containment.py"):
        return out
    threshold_words = ("MAX", "LIMIT", "BUDGET", "THRESHOLD", "CAP", "QUOTA", "TIMEOUT", "FLOOR")
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not all(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets):
            continue
        if not any(w in node.targets[0].id for w in threshold_words):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, float)):
            out.append(Finding(path, node.lineno, "policy_scatter", LOW,
                               f"{node.targets[0].id} is a threshold living outside a policy file"))
    return out


RULES = [
    rule_peer_authority,
    rule_length_before_bound,
    rule_deque_without_maxlen,
    rule_mutable_default,
    rule_bare_except,
    rule_string_identity,
    rule_ratio_without_floor,
    rule_policy_scatter,
]


def load_allowlist(path: Path = ALLOWLIST) -> dict[tuple[str, str], str]:
    allowed: dict[tuple[str, str], str] = {}
    if not path.exists():
        return allowed
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        target, sep, reason = line.partition("  #")
        if not sep or len(reason.strip()) < 20:
            raise SystemExit(f"allowlist entry without a reason: {raw!r}")
        place, _, rule = target.strip().rpartition(":")
        allowed[(place.strip(), rule.strip())] = reason.strip()
    return allowed


def review(paths: list[Path] | None = None, allowlist: dict | None = None) -> list[Finding]:
    allowed = load_allowlist() if allowlist is None else allowlist
    findings: list[Finding] = []
    for base in (paths or TARGETS):
        for file in sorted(base.rglob("*.py")):
            rel = str(file.relative_to(ROOT))
            tree = ast.parse(file.read_text(), filename=rel)
            for rule in RULES:
                for finding in rule(tree, rel):
                    if (rel, finding.rule) in allowed:
                        continue
                    findings.append(finding)
    return findings


def main(argv: list[str]) -> int:
    if "--list" in argv:
        for rule in RULES:
            print(f"{rule.__name__:34} {rule.__doc__ or ''}".rstrip())
        return 0
    findings = review()
    for f in sorted(findings, key=lambda x: (x.severity != HIGH, x.path, x.line)):
        print(f.render())
    high = [f for f in findings if f.severity == HIGH]
    print(f"\n{len(findings)} finding(s), {len(high)} high")
    return 1 if high else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
