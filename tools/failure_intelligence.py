#!/usr/bin/env python3
"""Failure intelligence: turn each failure into something that improves the system.

`self_review.py` detects. This module explains, classifies, tracks, and proposes. It is
deliberately unable to do anything else. There is no suppression API, no status setter, no
"mark fixed" call, and no write path to the exemption list. A finding moves to resolved only
when the ledger record itself carries a witness: a reproduction that exists and a regression
test that exists. Evidence and human review govern acceptance; this tool only assembles it.

Six categories, because a failure is not automatically a vulnerability:

    code_defect             the application is wrong             fix the code
    analyzer_defect         detection is wrong, either direction  fix the detection
    test_defect             the test asserts the wrong thing      repair the test
    coverage_gap            a known behaviour is unverified       add a reproduction
    policy_failure          the rule exists nowhere               define the policy
    infrastructure_failure  the execution environment is broken   repair execution

Fields are separated on purpose. `observed` holds facts the analyzer can point at, and the
validator rejects hedging language there: "the value arrives from struct.unpack" is observed,
"the peer may control the allocation" is inferred risk and belongs in `why_matters`. Mixing
them is how a guess acquires the authority of a measurement.

    python tools/failure_intelligence.py              # terminal report
    python tools/failure_intelligence.py --intel      # patterns across failures
    python tools/failure_intelligence.py --json       # machine-readable
    python tools/failure_intelligence.py --sarif out.sarif
    python tools/failure_intelligence.py --check      # exit 1 on open high findings
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "harness" / "findings.jsonl"
ID_PATTERN = re.compile(r"^SR-[A-Z]+-\d{3}$")
LOCATION_PATTERN = re.compile(r"^[A-Za-z0-9_./-]+:\d+$")
HEDGES = (" may ", " might ", " could ", " likely ", " probably ", " possibly ", " perhaps ")

CATEGORIES = {
    "code_defect": "fix application code",
    "analyzer_defect": "fix detection logic",
    "test_defect": "repair the test",
    "coverage_gap": "add a reproduction",
    "policy_failure": "define the policy",
    "infrastructure_failure": "repair execution",
}
SEVERITIES = ("high", "medium", "low")
CONFIDENCES = ("observed", "inferred", "verified")
STATUSES = ("open", "resolved", "rejected")


@dataclass
class Finding:
    finding_id: str
    category: str
    severity: str
    confidence: str
    location: str
    rule: str
    observed: str
    why_matters: str
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    next_action: str = ""
    subcategory: str = ""
    assumption: str = ""
    reproduction: str | None = None
    regression_test: str | None = None
    root_cause: str = ""
    status: str = "open"

    def problems(self) -> list[str]:
        """Everything wrong with this record, so the ledger can refuse to load it."""
        out = []
        if not ID_PATTERN.match(self.finding_id):
            out.append(f"{self.finding_id!r} is not SR-CLASS-NNN")
        if self.category not in CATEGORIES:
            out.append(f"unknown category {self.category!r}")
        if self.severity not in SEVERITIES:
            out.append(f"unknown severity {self.severity!r}")
        if self.confidence not in CONFIDENCES:
            out.append(f"unknown confidence {self.confidence!r}")
        if self.status not in STATUSES:
            out.append(f"unknown status {self.status!r}")
        if not LOCATION_PATTERN.match(self.location):
            out.append(f"location {self.location!r} is not path:line")
        if not self.observed.strip():
            out.append("no observed facts recorded")
        if any(hedge in f" {self.observed.lower()} " for hedge in HEDGES):
            out.append("observed contains hedging language; inference belongs in why_matters")
        if not self.why_matters.strip():
            out.append("no risk statement recorded")
        if not self.next_action.strip():
            out.append("no next action recorded")
        if not self.evidence:
            out.append("no evidence entries")
        if self.confidence == "verified" and not (self.reproduction and self.evidence):
            out.append("verified confidence requires a reproduction and evidence")
        if self.status == "resolved" and not (self.regression_test and (self.reproduction or self.evidence)):
            out.append("resolved without a witness: needs a regression test and a reproduction or evidence")
        if self.status == "rejected" and not self.evidence:
            out.append("rejected without evidence; a refusal needs its own proof")
        return out

    @property
    def path_and_line(self) -> tuple[str, int]:
        path, line = self.location.rsplit(":", 1)
        return path, int(line)


def load(path: Path | None = None) -> list[Finding]:
    path = path or LEDGER
    findings, seen = [], set()
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("//"):
            continue
        record = json.loads(raw)
        finding = Finding(**record)
        problems = finding.problems()
        if problems:
            raise SystemExit(f"{path.name}:{number} {finding.finding_id}: " + "; ".join(problems))
        if finding.finding_id in seen:
            raise SystemExit(f"{path.name}:{number}: duplicate id {finding.finding_id}")
        seen.add(finding.finding_id)
        findings.append(finding)
    return findings


def render(findings: list[Finding]) -> str:
    """Terminal report. Facts, then risk, then evidence, then what the tool cannot see."""
    blocks = []
    for f in findings:
        lines = [
            f"Finding: {f.finding_id}",
            f"Category: {f.category}  ({CATEGORIES[f.category]})",
            f"Severity: {f.severity.upper()}",
            f"Confidence: {f.confidence}",
            f"Status: {f.status}",
            f"Location: {f.location}",
            "",
            "Observed:",
            f"  {f.observed}",
            "",
            "Why it matters:",
            f"  {f.why_matters}",
            "",
            "Evidence:",
            *[f"  - {e}" for e in f.evidence],
            "",
            "Limitations:",
            *([f"  - {l}" for l in f.limitations] or ["  - none recorded"]),
            "",
            "Next action:",
            f"  {f.next_action}",
        ]
        if f.reproduction:
            lines += ["", f"Reproduction: python tools/repro.py {f.reproduction}"]
        if f.regression_test:
            lines += [f"Regression:   {f.regression_test}"]
        blocks.append("\n".join(lines))
    counts = Counter(f.category for f in findings)
    summary = ", ".join(f"{n} {c}" for c, n in sorted(counts.items())) or "none"
    open_high = [f.finding_id for f in findings if f.status == "open" and f.severity == "high"]
    blocks.append(f"{len(findings)} finding(s): {summary}")
    if open_high:
        blocks.append("open high: " + ", ".join(open_high))
    return "\n\n".join(blocks)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)


def to_sarif(findings: list[Finding]) -> str:
    levels = {"high": "error", "medium": "warning", "low": "note"}
    rules, results = {}, []
    for f in findings:
        rules.setdefault(f.rule, {
            "id": f.rule,
            "name": f.rule,
            "shortDescription": {"text": f.why_matters[:200]},
            "defaultConfiguration": {"level": levels[f.severity]},
            "properties": {"category": f.category, "nextAction": f.next_action},
        })
        path, line = f.path_and_line
        results.append({
            "ruleId": f.rule,
            "level": levels[f.severity],
            "message": {"text": f"{f.finding_id} [{f.category}] {f.observed}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": line},
            }}],
            "partialFingerprints": {"findingId": f.finding_id},
            "properties": {"category": f.category, "confidence": f.confidence, "status": f.status},
        })
    document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "adversarial-code-reviewer-corpus failure intelligence",
                "version": "1.0.0",
                "informationUri": "https://github.com/1243353366/adversarial-code-reviewer-corpus",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(document, indent=2)


def intelligence(findings: list[Finding], allowlist_path: Path | None = None) -> dict[str, list[str]]:
    """Where the review system itself is unreliable. Proposals only, never verdicts."""
    out: dict[str, list[str]] = defaultdict(list)

    misses = Counter(f.rule for f in findings if f.category == "analyzer_defect" and f.subcategory == "false_negative")
    for rule, count in misses.items():
        out["analyzers_missing_defects"].append(f"{rule}: {count} false negative(s) recorded")

    noise = Counter(f.rule for f in findings if f.category == "analyzer_defect" and f.subcategory == "false_positive")
    for rule, count in noise.items():
        out["analyzers_crying_wolf"].append(f"{rule}: {count} false positive(s) recorded")

    clusters = defaultdict(list)
    for f in findings:
        if f.assumption:
            clusters[f.assumption].append(f.finding_id)
    for assumption, ids in clusters.items():
        if len(ids) >= 2:
            out["review_agenda"].append(
                f"assumption '{assumption}' is load-bearing in {len(ids)} findings ({', '.join(ids)}); "
                f"review every rule that relies on it, not just the rule that broke")

    resolved_rules = {f.rule for f in findings if f.status == "resolved"}
    for f in findings:
        if f.status == "open" and f.rule in resolved_rules:
            out["recurrence"].append(f"{f.rule} has an open finding again after an earlier resolution ({f.finding_id})")

    policy = [f.finding_id for f in findings if f.category == "policy_failure" and f.status == "open"]
    if policy:
        out["policy_debt"].append("open policy failures: " + ", ".join(policy))

    path = allowlist_path or (ROOT / "harness" / "self_review_allow.txt")
    if path.exists():
        per_file: Counter = Counter()
        for line in path.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#") and ":" in line:
                per_file[line.split(":")[0].strip()] += 1
        for target, count in per_file.items():
            if count >= 2:
                out["exemption_hotspots"].append(f"{target}: {count} exemptions; a file needing this many is usually a design question")

    for f in findings:
        if f.category == "coverage_gap" and f.status == "open":
            out["coverage_debt"].append(f"{f.finding_id}: {f.location} — {f.next_action}")
    return dict(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Explain, classify and track review failures.")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--sarif", nargs="?", const=str(ROOT / "findings.sarif"), help="write SARIF")
    parser.add_argument("--intel", action="store_true", help="patterns across failures only")
    parser.add_argument("--check", action="store_true", help="exit 1 when an open high finding exists")
    args = parser.parse_args(argv)

    findings = load()
    if args.json:
        print(to_json(findings))
    elif args.sarif:
        Path(args.sarif).write_text(to_sarif(findings))
        print(f"wrote {args.sarif}")
    elif args.intel:
        report = intelligence(findings)
        if not report:
            print("no patterns across failures yet")
        for heading, items in report.items():
            print(f"{heading}:")
            for item in items:
                print(f"  - {item}")
    else:
        print(render(findings))

    open_high = [f for f in findings if f.status == "open" and f.severity == "high"]
    if args.check and open_high:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
