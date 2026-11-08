#!/usr/bin/env python3
"""Classify a failure by mechanism, from evidence, or abstain.

This is a proposal engine. It reads structured evidence codes, matches them against a
closed rule table, and emits a proposal with the evidence that produced it. It does not read
prose, it does not edit the ledger, and it does not decide that anything is fixed.

Why codes and not text: a classifier that reads a report's wording learns the vocabulary of
whoever wrote the report. The same defect described as "unsound bound" and "missing clamp"
would land in two categories, and a defect described with confidence and no evidence would
outrank one described plainly with a failing reproduction. Evidence codes are extracted
from what is checkable (does the reproduction exist, does it fail without the fix, is the
site the defect claims a site that performs that operation), so the mechanism decision
rests on facts rather than phrasing.

Three dimensions, kept apart because they are not exclusive. One failure has one component,
one mode and one mechanism, but "an analyzer defect that is also a coverage gap" is
representable instead of having to pick. The single-label scheme this replaces could not
express that, and forced a false either/or at classification time.

    nist_sp800_231     bugs, faults, weaknesses distinguished by role and causal chain
    ieee_1044_2009     what an anomaly record contains across the lifecycle (inactive;
                       reference only, not a current mandatory standard)
    arxiv_2408_13855   empirical mechanisms behind analyzer false positives and negatives
    fse_2024           automated oracles for analyzer defects, soundness and precision
    cwe                weakness categories, for product defects only; a CI misconfiguration
                       is not a CWE and is not coerced into one

Mechanism vocabulary is drawn from those sources and from this repository's own history. It
is deliberately small: a vocabulary that grows with every incident stops being comparable.

    python tools/failure_classifier.py                # proposals for the ledger
    python tools/failure_classifier.py --eval         # precision, recall, abstention
    python tools/failure_classifier.py --json
    python tools/failure_classifier.py --codes '["claim_unreproducible"]'
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = ROOT / "harness" / "classification_benchmark.jsonl"
sys.path.insert(0, str(ROOT / "tools"))

import failure_intelligence as fi  # noqa: E402

COMPONENTS = ("product", "analyzer", "test", "policy", "infrastructure")
MODES = ("false_positive", "false_negative", "missing_coverage", "incorrect_oracle",
         "invalid_configuration", "execution_failure", "specification_ambiguity", "unverified_claim")
MECHANISMS = ("semantic_model_error", "control_flow_reasoning_error", "incomplete_data_flow",
              "scope_confinement_error", "suppression_granularity_error", "availability_error",
              "threshold_decentralization", "coverage_of_pattern_error", "site_mismatch",
              "oracle_error", "unreproducible_claim")
CONFIDENCES = ("supported", "probable", "insufficient_evidence")

# The closed evidence vocabulary. Each code is a checkable fact about the failure, and the
# extractor that fills it is named beside it.
EVIDENCE_CODES = {
    "expected_finding_actual_none": "the analyzer produced no finding on an input that has the defect",
    "expected_none_actual_finding": "the analyzer produced a finding on an input that has no defect",
    "reported_site_cannot_contain_defect": "the cited line does not perform the operation the finding describes",
    "reproduction_fails_without_fix": "reproductions/repro.py demonstrates the failure against the pre-fix code",
    "reproduction_absent": "no reproduction exists for the claim",
    "regression_test_absent": "no test pins the corrected behaviour",
    "pattern_has_no_fixture": "no repository fixture instantiates the defect class",
    "suppression_coarser_than_reason": "an exemption suppresses more than its written reason describes",
    "threshold_outside_policy": "a defensive limit is declared where it is used, not in a policy",
    "control_not_exercised": "the control reported success without running the case it guards",
    "execution_precedes_test": "the pipeline stops before the relevant check executes",
    "test_asserts_wrong_behaviour": "the test's assertion accepts the behaviour under review",
    "claim_unreproducible": "the reported mechanism does not reproduce against the named code",
    "analyzer_bounds_model": "the defect is in how the analyzer decides a value is bounded",
    "analyzer_guard_model": "the defect is in how the analyzer reads a rejecting guard",
    "analyzer_scope_model": "the defect is in which scope a fact is attributed to",
    "analyzer_propagation_model": "the defect is in how far a fact is propagated",
}


@dataclass(frozen=True)
class Rule:
    name: str
    requires: frozenset
    component: str
    mode: str
    mechanism: str
    source: str


RULES = (
    Rule("unbounded value accepted as bounded", frozenset({"expected_finding_actual_none",
         "reproduction_fails_without_fix", "analyzer_bounds_model"}),
         "analyzer", "false_negative", "semantic_model_error", "arxiv_2408_13855"),
    Rule("guard credited without a rejection path", frozenset({"expected_finding_actual_none",
         "reproduction_fails_without_fix", "analyzer_guard_model"}),
         "analyzer", "false_negative", "control_flow_reasoning_error", "fse_2024"),
    Rule("fact attributed to the wrong scope", frozenset({"expected_finding_actual_none",
         "reproduction_fails_without_fix", "analyzer_scope_model"}),
         "analyzer", "false_negative", "scope_confinement_error", "arxiv_2408_13855"),
    Rule("propagation stopped short", frozenset({"expected_finding_actual_none",
         "reproduction_fails_without_fix", "analyzer_propagation_model"}),
         "analyzer", "false_negative", "incomplete_data_flow", "fse_2024"),
    Rule("finding filed against a site that cannot hold it", frozenset({"reported_site_cannot_contain_defect"}),
         "analyzer", "false_positive", "site_mismatch", "nist_sp800_231"),
    Rule("assertion accepts the wrong behaviour", frozenset({"test_asserts_wrong_behaviour"}),
         "test", "incorrect_oracle", "oracle_error", "ieee_1044_2009"),
    Rule("defect class has no fixture", frozenset({"pattern_has_no_fixture"}),
         "test", "missing_coverage", "coverage_of_pattern_error", "ieee_1044_2009"),
    Rule("suppression wider than its reason", frozenset({"suppression_coarser_than_reason"}),
         "policy", "invalid_configuration", "suppression_granularity_error", "nist_sp800_231"),
    Rule("control ran without exercising its case", frozenset({"control_not_exercised"}),
         "infrastructure", "invalid_configuration", "availability_error", "ieee_1044_2009"),
    Rule("limits scattered outside policy", frozenset({"threshold_outside_policy"}),
         "policy", "specification_ambiguity", "threshold_decentralization", "nist_sp800_231"),
    Rule("claim that will not reproduce", frozenset({"claim_unreproducible"}),
         "analyzer", "unverified_claim", "unreproducible_claim", "fse_2024"),
)


@dataclass
class Proposal:
    subject: str
    component: str | None
    mode: str | None
    mechanism: str | None
    confidence: str
    rule: str | None = None
    taxonomy_source: str | None = None
    evidence_refs: list[dict] = field(default_factory=list)
    contradicted_by: list[str] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
    evidence_codes: list[str] = field(default_factory=list)

    @property
    def abstained(self) -> bool:
        return self.confidence == "insufficient_evidence"


def _confidence(codes: set[str], refs: list[dict]) -> str:
    """How strong is the case for the classification, not for calling something fixed.

    A rule match is itself evidence: the codes that satisfied it are checkable facts. So the
    floor after a match is `probable`, and a surviving witness plus a failing reproduction
    raises it to `supported`. `insufficient_evidence` is reserved for the cases where no
    classification was reached at all, which is a different claim from a weak one. Conflating
    the two would have made a conclusive infrastructure diagnosis abstain merely because it
    had no reproduction, and a taxonomy that abstains on its clearest cases teaches nothing.
    """
    has_repro = "reproduction_fails_without_fix" in codes or "claim_unreproducible" in codes
    has_witness = any(r["kind"] in {"reproduction", "test", "source"} for r in refs)
    return "supported" if (has_repro and has_witness) else "probable"


def propose(subject: str, codes: list[str], refs: list[dict] | None = None) -> Proposal:
    """Map evidence codes onto the taxonomy. Abstains rather than guessing."""
    refs = refs or []
    given = set(codes)
    unknown = sorted(given - set(EVIDENCE_CODES))
    if unknown:
        return Proposal(subject, None, None, None, "insufficient_evidence",
                        missing_information=[f"unrecognised evidence code(s): {', '.join(unknown)}"],
                        evidence_codes=sorted(given))
    if not given:
        return Proposal(subject, None, None, None, "insufficient_evidence",
                        missing_information=["no evidence codes supplied"], evidence_codes=[])

    hits = [r for r in RULES if r.requires <= given]
    if not hits:
        needed = sorted({code for r in RULES for code in r.requires} - given)
        return Proposal(subject, None, None, None, "insufficient_evidence",
                        missing_information=[f"no rule matched; missing any of: {', '.join(needed[:6])}"],
                        evidence_codes=sorted(given))
    if len(hits) > 1:
        return Proposal(subject, None, None, None, "insufficient_evidence",
                        contradicted_by=[f"rules {h.name!r} and {h.requires.__class__.__name__}"
                                         for h in hits],
                        missing_information=["evidence supports more than one mechanism: "
                                             + ", ".join(r.name for r in hits)],
                        evidence_codes=sorted(given))

    rule = hits[0]
    contradictions = []
    if "reproduction_fails_without_fix" in given and "reproduction_absent" in given:
        contradictions.append("reproduction both present and absent")
    confidence = _confidence(given, refs)
    missing = [] if confidence == "supported" else ["a failing reproduction plus an existing witness"]
    return Proposal(subject, rule.component, rule.mode, rule.mechanism, confidence,
                    rule=rule.name, taxonomy_source=rule.source, evidence_refs=refs,
                    contradicted_by=contradictions, missing_information=missing,
                    evidence_codes=sorted(given))


def refs_for(finding) -> list[dict]:
    """Witnesses a finding already carries, checked for existence rather than believed."""
    refs = []
    if finding.reproduction:
        sys.path.insert(0, str(ROOT / "tools"))
        import repro

        known = {getattr(r, "id", getattr(r, "rid", "")) for r in repro.REGISTRY}
        if finding.reproduction in known:
            refs.append({"kind": "reproduction", "ref": finding.reproduction})
    if finding.regression_test:
        path, _, name = finding.regression_test.partition("::")
        file = ROOT / path
        if file.exists() and name in file.read_text():
            refs.append({"kind": "test", "ref": finding.regression_test})
    path, line = finding.path_and_line
    if (ROOT / path).exists():
        refs.append({"kind": "source", "ref": f"{path}:{line}"})
    return refs


def propose_for_ledger() -> list[Proposal]:
    return [propose(f.finding_id, list(f.evidence_codes), refs_for(f)) for f in fi.load()]


# --- evaluation: measured against labels a human wrote, never against its own output ------

def load_benchmark() -> list[dict]:
    return [json.loads(line) for line in BENCHMARK.read_text().splitlines() if line.strip()]


def evaluate() -> dict:
    cells: Counter = Counter()
    attempted: Counter = Counter()
    expected: Counter = Counter()
    abstain = {"correct": 0, "missed": 0, "unnecessary": 0}
    confusion = Counter()

    for row in load_benchmark():
        proposal = propose(row["case_id"], row["evidence_codes"], row.get("refs") or [])
        wants_abstain = row.get("expect") == "abstain"
        if proposal.abstained:
            abstain["correct" if wants_abstain else "missed"] += 1
            if not wants_abstain:
                confusion[(row.get("expected_component"), row.get("expected_mode"),
                           "abstained")] += 1
            continue
        if wants_abstain:
            abstain["unnecessary"] += 1
            confusion[("abstain", "abstain", f"{proposal.component}/{proposal.mode}")] += 1
            continue
        key = (proposal.component, proposal.mode)
        attempted[key] += 1
        truth = (row["expected_component"], row["expected_mode"])
        expected[truth] += 1
        if key == truth:
            cells[key] += 1
        else:
            confusion[(*truth, f"{proposal.component}/{proposal.mode}")] += 1

    per_cell = {f"{c}/{m}": {
        "proposed": attempted[(c, m)],
        "correct": cells[(c, m)],
        "precision": round(cells[(c, m)] / attempted[(c, m)], 3) if attempted[(c, m)] else None,
        "recall": round(cells[(c, m)] / expected[(c, m)], 3) if expected[(c, m)] else None,
    } for c, m in set(attempted) | set(expected)}

    total = len(load_benchmark())
    return {
        "cases": total,
        "per_cell": dict(sorted(per_cell.items())),
        "abstention": {**abstain, "rate": round(sum(abstain.values()) / total, 3)},
        "confusion": [{"expected": f"{e[0]}/{e[1]}", "proposed": e[2], "count": n}
                      for e, n in sorted(confusion.items())],
    }


def render(proposals: list[Proposal]) -> str:
    lines = []
    for p in proposals:
        if p.abstained:
            lines.append(f"{p.subject}: ABSTAIN — {'; '.join(p.missing_information or p.contradicted_by)}")
            continue
        lines.append(f"{p.subject}: {p.component} / {p.mode} / {p.mechanism} "
                     f"[{p.confidence}] rule={p.rule} source={p.taxonomy_source} "
                     f"witnesses={','.join(r['ref'] for r in p.evidence_refs) or 'none'}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Propose a classification for each failure.")
    parser.add_argument("--eval", action="store_true", help="score against the labelled benchmark")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--codes", help="classify an ad hoc evidence-code list")
    args = parser.parse_args(argv)

    if args.codes:
        codes = json.loads(args.codes)
        print(render([propose("adhoc", codes)]))
        return 0
    if args.eval:
        report = evaluate()
        print(json.dumps(report, indent=2))
        return 0
    proposals = propose_for_ledger()
    print(json.dumps([asdict(p) for p in proposals], indent=2) if args.json else render(proposals))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
