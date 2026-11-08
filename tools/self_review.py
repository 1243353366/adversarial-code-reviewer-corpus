#!/usr/bin/env python3
"""A reviewer that reads this repository's own code, using the rules it keeps writing down.

Every rule here is a defect class the corpus already catalogued from someone else's work,
applied back to the modules that do the cataloguing. Findings are reported with file, line,
rule and one sentence on why it matters.

    python tools/self_review.py            # human table, exit 1 on any high severity
    python tools/self_review.py --list     # rules only

Exemptions are occurrence-specific. An entry names the file, the rule and a fingerprint of
the exact source line, so exempting one read of a peer field cannot silently exempt the next
one added to the same file. An entry that matches no current finding is stale and fails the
run; an entry that matches more than one is ambiguous and also fails.

What this is not. The analysis is intraprocedural, path-insensitive and blind to values that
travel through containers, attributes or function returns. `rule_length_before_bound` follows
assignment and conversion chains inside one function and treats a comparison against a
threshold as validation; it does not prove a bound exists, only that none is visible. A clean
run means none of these eight rules found a defect it can see, not that the code is correct.
"""
from __future__ import annotations

import ast
import hashlib
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [ROOT / "harness", ROOT / "tools"]
ALLOWLIST = ROOT / "harness" / "self_review_allow.txt"
PEER_AUTH_KEYS = {"role", "origin", "cmd", "admin", "scope", "authenticated"}
PAYLOAD_NAMES = {"msg", "payload", "body", "message", "data", "envelope", "frame"}
SIZE_CALLS = {"read_exact", "recv", "allocate", "bytearray", "read"}
PASSTHROUGH = {"int", "float", "abs", "str", "bool"}
UPPER_CLAMPS = {"min"}   # min(x, LIMIT) can cap; max(x, 1) only floors
LOWER_CLAMPS = {"max"}

HIGH, MEDIUM, LOW = "high", "medium", "low"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    why: str
    fingerprint: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.path, self.rule, self.fingerprint)

    def render(self) -> str:
        return f"{self.path}:{self.line}  {self.severity:6} {self.rule:28} {self.why}"


def fingerprint_of(source_line: str) -> str:
    """Stable across line shifts, and specific enough that a different line differs."""
    normalised = re.sub(r"\s+", " ", source_line).strip()
    return hashlib.sha1(normalised.encode()).hexdigest()[:8]


def _scope_nodes(scope: ast.AST):
    """Nodes in one function body, without descending into nested scopes."""
    stack = list(getattr(scope, "body", []))
    while stack:
        node = stack.pop(0)
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _scopes(tree: ast.AST):
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _assigns(scope: ast.AST):
    for node in _scope_nodes(scope):
        if isinstance(node, ast.Assign):
            yield node
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            yield ast.Assign(targets=[node.target], value=node.value)


def _target_names(targets) -> list[str]:
    """Names bound by an assignment, unwrapping tuple and list unpacking."""
    out: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            out.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            out.extend(_target_names(target.elts))
        elif isinstance(target, ast.Starred):
            out.extend(_target_names([target.value]))
    return out


def _call_name(call: ast.Call) -> str:
    func = call.func
    return getattr(func, "attr", getattr(func, "id", ""))


def rule_peer_authority(tree: ast.AST, path: str) -> list[Finding]:
    """Authorization decided from a field the peer wrote."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            if node.value.id not in PAYLOAD_NAMES:
                continue
            if isinstance(node.slice, ast.Constant) and node.slice.value in PEER_AUTH_KEYS:
                out.append(Finding(path, node.lineno, "peer_authority_from_payload", HIGH,
                                   f"'{node.slice.value}' read from a peer-supplied mapping"))
        if isinstance(node, ast.Call) and _call_name(node) == "get":
            if not isinstance(node.func.value, ast.Name) or node.func.value.id not in PAYLOAD_NAMES:
                continue
            if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in PEER_AUTH_KEYS:
                out.append(Finding(path, node.lineno, "peer_authority_from_payload", HIGH,
                                   f"'{node.args[0].value}' read from a peer-supplied mapping"))
    return out


def _is_limit(node: ast.AST) -> bool:
    """A constant or an upper-case threshold, which is how limits are spelled here."""
    return (isinstance(node, ast.Constant) and isinstance(node.value, (int, float))) or (
        isinstance(node, ast.Name) and node.id.isupper())


def _reject_guards(scope: ast.AST) -> set[str]:
    """Names whose out-of-range branch exits, so later use is bounded by an upper limit.

    `if n < MAX: pass` does not qualify: the comparison is present but nothing rejects the
    unsafe value, and crediting it was R64. Only a guard whose body raises, returns, breaks
    or continues counts. The analysis is still path-insensitive: it credits the whole scope
    once such a guard exists, so a second unsafe use before the guard is not modelled.
    """
    bounded: set[str] = set()
    exits = (ast.Raise, ast.Return, ast.Continue, ast.Break)
    for node in _scope_nodes(scope):
        if not isinstance(node, ast.If):
            continue
        if not any(isinstance(stmt, exits) for stmt in node.body):
            continue
        for cmp in [n for n in ast.walk(node.test) if isinstance(n, ast.Compare)]:
            if len(cmp.ops) != 1:
                continue
            op, left, right = cmp.ops[0], cmp.left, cmp.comparators[0]
            if isinstance(left, ast.Name) and _is_limit(right) and isinstance(op, (ast.Gt, ast.GtE)):
                bounded.add(left.id)
            elif isinstance(right, ast.Name) and _is_limit(left) and isinstance(op, (ast.Lt, ast.LtE)):
                bounded.add(right.id)
    return bounded


def _taint_analysis(scope: ast.AST) -> tuple[set[str], set[str]]:
    """Names carrying wire-derived values, and names a visible check or clamp has bounded.

    Seeded by `struct.unpack`, followed through assignments, conversions and arithmetic.
    A name is considered bounded when it is clamped by min/max or compared against a
    numeric constant or an upper-case threshold, because this codebase rejects on that
    comparison. The second case is an assumption, not a proof: it cannot see whether the
    reject branch actually returns.
    """
    tainted: set[str] = set()
    bounded: set[str] = set()
    assigns = list(_assigns(scope))
    # iterate to a fixpoint: a chain can be arbitrarily long, and a fixed budget is a
    # depth limit dressed as data flow. The assignment count bounds the work.
    for _ in range(len(assigns) + 2):
        for node in assigns:
            value = node.value
            if isinstance(value, ast.Call) and _call_name(value) == "unpack":
                tainted.update(_target_names(node.targets))
                continue
            origin = _expr_taint(value, tainted)
            if not origin:
                continue
            names = _target_names(node.targets)
            if isinstance(value, ast.Call) and _call_name(value) in UPPER_CLAMPS and \
                    any(_is_limit(arg) for arg in value.args):
                bounded.update(names)
            else:
                tainted.update(names)
    bounded |= _reject_guards(scope)
    return tainted, bounded


def _expr_taint(expr: ast.AST, tainted: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in tainted:
            return True
        if isinstance(node, ast.Call) and _call_name(node) == "unpack":
            return True
    return False


def _unguarded_size_names(expr: ast.AST, tainted: set[str], bounded: set[str]) -> set[str]:
    """Wire-derived names in a size expression, ignoring anything a clamp already bounds."""
    out: set[str] = set()

    def walk(node: ast.AST) -> None:
        if isinstance(node, ast.Call) and _call_name(node) in UPPER_CLAMPS \
                and any(_is_limit(arg) for arg in node.args):
            return
        if isinstance(node, ast.Name) and node.id in tainted and node.id not in bounded:
            out.add(node.id)
        for child in ast.iter_child_nodes(node):
            walk(child)

    walk(expr)
    return out


def rule_length_before_bound(tree: ast.AST, path: str) -> list[Finding]:
    """A wire-derived length used as an allocation or read size, through aliases and casts."""
    out = []
    for scope in _scopes(tree):
        tainted, bounded = _taint_analysis(scope)
        if not tainted:
            continue
        for node in _scope_nodes(scope):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            if _call_name(node) not in SIZE_CALLS:
                continue
            risky = _unguarded_size_names(node.args[0], tainted, bounded)
            if risky:
                out.append(Finding(path, node.lineno, "peer_length_before_bound", HIGH,
                                   f"'{sorted(risky)[0]}' came from the wire and reaches a size "
                                   f"with no visible bound"))
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
        if not isinstance(node, ast.Compare):
            continue
        sides = [node.left, *node.comparators]
        for a, b in zip(sides, sides[1:]):
            label = getattr(a, "id", None) or getattr(a, "attr", None) or ""
            if label in {"origin", "cap", "capability", "role"} and isinstance(b, ast.Constant) \
                    and isinstance(b.value, str):
                out.append(Finding(path, node.lineno, "string_identity_compare", HIGH,
                                   f"{label} compared to a literal, so any writer can spell it"))
    return out


def rule_ratio_without_floor(tree: ast.AST, path: str) -> list[Finding]:
    """A ratio whose denominator can be zero, judged inside the scope that does the division."""
    out = []
    if not path.startswith("harness/"):
        return out  # authoring scripts compute over their own lists, not over peer input
    for scope in _scopes(tree):
        floored: set[str] = set()
        for node in _assigns(scope):
            v = node.value
            if isinstance(v, ast.Call) and _call_name(v) in LOWER_CLAMPS and any(
                    _is_limit(arg) for arg in v.args):
                floored.update(_target_names(node.targets))
        for node in _scope_nodes(scope):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
                continue
            denom = node.right
            guarded = (isinstance(denom, ast.Call) and _call_name(denom) in LOWER_CLAMPS) or (
                isinstance(denom, ast.Name) and denom.id in floored)
            if not guarded and isinstance(denom, (ast.Name, ast.Attribute)):
                out.append(Finding(path, node.lineno, "ratio_without_floor", HIGH,
                                   "denominator is unguarded in this scope, so an empty request yields NaN"))
    return out


def rule_policy_scatter(tree: ast.AST, path: str) -> list[Finding]:
    """Thresholds declared per module are policy that nobody can inspect in one place."""
    out = []
    if not path.startswith("harness/") or path.endswith("containment.py"):
        return out
    words = ("MAX", "LIMIT", "BUDGET", "THRESHOLD", "CAP", "QUOTA", "TIMEOUT", "FLOOR")
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not all(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets):
            continue
        if not any(w in node.targets[0].id for w in words):
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
RULE_NAMES = {
    "peer_authority_from_payload",
    "peer_length_before_bound",
    "unbounded_queue",
    "mutable_default",
    "bare_except",
    "string_identity_compare",
    "ratio_without_floor",
    "policy_scatter",
}


def load_allowlist(path: Path = ALLOWLIST) -> dict[tuple[str, str, str], str]:
    """Entries are `path:rule:fingerprint  # reason`. Anything looser is a suppression."""
    allowed: dict[tuple[str, str, str], str] = {}
    if not path.exists():
        return allowed
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        target, sep, reason = line.partition("  #")
        if not sep or len(reason.strip()) < 20:
            raise SystemExit(f"{path.name}:{number}: exemption without a written reason: {raw!r}")
        place, rule, fp = (target.strip().split(":") + ["", ""])[:3]
        if rule not in RULE_NAMES:
            raise SystemExit(f"{path.name}:{number}: unknown rule {rule!r}")
        if not re.fullmatch(r"[0-9a-f]{8}", fp):
            raise SystemExit(f"{path.name}:{number}: exemption is not occurrence-specific; "
                             f"expected path:rule:fingerprint")
        if not (ROOT / place).exists():
            raise SystemExit(f"{path.name}:{number}: no such file {place!r}")
        key = (place, rule, fp)
        if key in allowed:
            raise SystemExit(f"{path.name}:{number}: duplicate exemption for {place}:{rule}:{fp}")
        allowed[key] = reason.strip()
    return allowed


def _collect(paths: list[Path] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for base in (paths or TARGETS):
        for file in sorted(base.rglob("*.py")):
            rel = str(file.relative_to(ROOT))
            text = file.read_text()
            lines = text.splitlines()
            tree = ast.parse(text, filename=rel)
            for rule in RULES:
                for finding in rule(tree, rel):
                    source = lines[finding.line - 1] if finding.line <= len(lines) else ""
                    findings.append(replace(finding, fingerprint=fingerprint_of(source)))
    return findings


def apply_allowlist(findings: list[Finding], allowed: dict[tuple[str, str, str], str]) -> list[Finding]:
    """Exempt exactly one occurrence per entry. Stale and ambiguous entries are errors."""
    remaining = list(findings)
    for key, reason in allowed.items():
        matches = [f for f in remaining if f.key == key]
        if not matches:
            raise SystemExit(f"stale exemption (matches nothing): {key[0]}:{key[1]}:{key[2]} — {reason}")
        if len(matches) > 1:
            raise SystemExit(f"ambiguous exemption (matches {len(matches)} findings): "
                             f"{key[0]}:{key[1]}:{key[2]} — distinguish the occurrences first")
        remaining.remove(matches[0])
    return remaining


def review(paths: list[Path] | None = None, allowlist: dict | None = None) -> list[Finding]:
    allowed = load_allowlist() if allowlist is None else allowlist
    return apply_allowlist(_collect(paths), allowed)


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
