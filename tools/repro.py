#!/usr/bin/env python3
"""Reproductions for every defect the CHANGELOG claims.

Each entry reconstructs the defect in its historical form, runs the current guard against
it, and reports whether the guard catches it. A changelog row without a passing repro is a
claim, not a record.

    python tools/repro.py --list     # every defect id and what it reconstructs
    python tools/repro.py --check    # run all, exit non-zero if any escapes
    python tools/repro.py <id>       # one entry, verbose
"""
from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, NamedTuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_protection as CP  # noqa: E402
import validate_corpus as V  # noqa: E402

META = V.load(ROOT / "corpus/out/research-metadata.json")
CLAIMS = V.load(ROOT / "corpus/out/claims.json")


class Repro(NamedTuple):
    id: str
    defect: str
    reconstructs: str
    run: Callable[[object], list[str]]
    historical: Callable[[], object]
    current: Callable[[], object]


def _md_text(name: str) -> str:
    return (ROOT / name).read_text()


def _errors(fn, *args) -> list[str]:
    return fn(*args)


def _mutated_meta(fn: Callable[[dict], None]) -> dict:
    m = copy.deepcopy(META)
    fn(m)
    return m


def _mutated_claims(fn: Callable[[dict], None]) -> dict:
    c = copy.deepcopy(CLAIMS)
    fn(c)
    return c


def _md_with(line: str) -> list[str]:
    """A tracked markdown path carrying an injected sentence."""
    tmp = Path(tempfile.mkdtemp()) / "injected.md"
    tmp.write_text(line + "\n")
    return [str(tmp)]


# --- corpus and evidence defects ------------------------------------------------

def r_status_attribution() -> list[str]:
    return V.check_status_language(
        _md_with("D1 is Accepted at TOSEM, so the finding is settled.")
    )


def r_tier_collapse() -> list[str]:
    def fold(m: dict):
        m["documents"][2]["peer_review_tier"] = "publisher_confirmed"
    return V.check_peer_review_tiers(_mutated_meta(fold))


def r_licence_overreach() -> list[str]:
    """The guard covers the partition. The prose claim it was written for has no automated
    check, and the changelog says so rather than implying this repro covers both."""
    def move(m: dict):
        obs = m["corpus_level_observations"]
        obs["redistributable"].append("D1")
        obs["non_redistributable"].remove("D1")
    return V.check_license_consistency(_mutated_meta(move))


def r_schema_unvalidated() -> list[str]:
    def drop(m: dict):
        m["documents"][0].pop("reproducibility", None)
    schema = json.loads((ROOT / "schemas/research-metadata.schema.json").read_text())
    return V.schema_errors(_mutated_meta(drop), schema)


def r_locator_unresolved() -> list[str]:
    def promote(c: dict):
        """An unavailable locator renamed to a section, keeping its verified claim status."""
        for cl in c["claims"]:
            if cl.get("locator_status") == "unavailable":
                cl["locator_status"] = "verified"
                cl["locator"]["section"] = "Section 4.2"
                break
    return V.check_locator_resolution(_mutated_claims(promote))


def r_replication_inflation() -> list[str]:
    def inflate(c: dict):
        c["claims"][0]["replication_status"] = "independent"
    return V.check_replication_claims(_mutated_claims(inflate), META)


def r_count_inflation() -> list[str]:
    def inflate(m: dict):
        m["corpus_level_observations"]["documents_verified"] = 9
    return V.check_corpus_counts(_mutated_meta(inflate))


def r_field_smuggling() -> list[str]:
    def smuggle(m: dict):
        m["documents"][0]["verified"] = True
    return V.check_extension_keys(_mutated_meta(smuggle))


def r_status_field_blindspot() -> list[str]:
    def assert_review(m: dict):
        m["documents"][3]["peer_review_status"] = "peer reviewed, ESORICS 2024"
    return V.check_status_fields(_mutated_meta(assert_review))


# --- paired state checks: history must fail, now must pass -----------------------
# Kind A entries mutate a corpus artifact. Kind B entries describe the state the defect
# lived in (a document revision, a control-plane setting) so the same assertion can be
# pointed at the pre-fix state and at the tree. A repro that only ever sees the fixed
# state proves nothing.

def _read(name: str) -> str:
    return (ROOT / name).read_text()


def _split_check(marker: str):
    """A prose check: the phrase must be present in the document."""
    def check(state: str) -> list[str]:
        return [] if marker in state else [f"missing required wording: {marker!r}"]
    return check


def _absent_check(*markers: str):
    def check(state: str) -> list[str]:
        return [f"forbidden wording present: {m!r}" for m in markers if m in state]
    return check


# R09: workflow reachable by Actions, dependencies not ignored
def r_workflow_location(state: dict) -> list[str]:
    errs = []
    if not state["workflow_at_expected_path"]:
        errs.append("workflow is not at .github/workflows/validate.yml; Actions never reads it")
    if state["requirements_ignored"]:
        errs.append("requirements-dev.txt matched an ignore rule; the workflow cannot install")
    if not state["requirements_tracked"]:
        errs.append("requirements-dev.txt is not in the tree")
    return errs


def _workflow_state() -> dict:
    return {
        "workflow_at_expected_path": (ROOT / ".github/workflows/validate.yml").exists(),
        "requirements_ignored": subprocess.run(
            ["git", "check-ignore", "-q", "requirements-dev.txt"], cwd=ROOT
        ).returncode == 0,
        "requirements_tracked": (ROOT / "requirements-dev.txt").exists(),
    }


# R10: required context is the job, not the workflow
REQUIRED_CONTEXT = "corpus"
WORKFLOW_NAME = "validate"


def r_required_context_name(state: dict) -> list[str]:
    errs = []
    if state["workflow_name"] != WORKFLOW_NAME:
        errs.append(f"workflow renamed: {state['workflow_name']!r}")
    if state["job_name"] != REQUIRED_CONTEXT:
        errs.append(f"job renamed: {state['job_name']!r}; protection requires {REQUIRED_CONTEXT!r}")
    if re.search(r"requires the `validate` (check|job)", state["readme"]):
        errs.append("README names the workflow as the required context")
    if f"`{REQUIRED_CONTEXT}` status check" not in state["readme"]:
        errs.append("README no longer names the required context as the job")
    return errs


def _context_state() -> dict:
    wf = _read(".github/workflows/validate.yml")
    name = re.search(r"^name:\s*(\S+)", wf, re.M)
    job = re.search(r"^jobs:\s*\n\s+(\w+):", wf, re.M)
    return {
        "workflow_name": name.group(1) if name else None,
        "job_name": job.group(1) if job else None,
        "readme": _read("README.md"),
    }


# R11: protection the pushing account can walk around
def r_protection_bypass(state: dict) -> list[str]:
    errs = []
    for key, want in state["required"].items():
        got = state["observed"].get(key)
        if got != want:
            errs.append(f"{key}: observed {got!r}, required {want!r}")
    return errs


def _protection_state() -> dict:
    rec = json.loads((ROOT / "harness/policy/protection.expected.json").read_text())
    return {"required": rec["required"], "observed": rec["recorded"]}


# R13/R14: harness prose requirements
def r_verdicts_required(state: str) -> list[str]:
    return [] if "verdict for **every** sample" in state else [
        "S6 does not require a verdict per sample; error vectors cannot be built from findings"
    ]


def r_fabrication_circular(state: str) -> list[str]:
    return [f"S4 does not report {p}" for p in
            ("pre-gate rate", "post-gate rate", "gate pass rate") if p not in state]


# R15/R16: oracle record
def r_oracle_manual_review(state: str) -> list[str]:
    errs = []
    if re.search(r'"oracle_binding":\s*"', state):
        errs.append("oracle_binding is a bare string")
    if re.search(r"manual-review\s*\|", state):
        errs.append("manual-review listed as an oracle kind")
    return errs


def r_oracle_identity(state: str) -> list[str]:
    block = re.search(r"```json\n(\{.*?\})\n```", state, re.S)
    if not block:
        return ["hypothesis record example missing"]
    binding = json.loads(block.group(1)).get("oracle_binding")
    if not isinstance(binding, dict):
        return ["oracle_binding is not structured"]
    errs = [f"oracle_binding lacks {f}" for f in
            ("kind", "oracle_id", "oracle_version", "ruleset_hash", "verdict") if f not in binding]
    if binding.get("verdict") not in ("not_run", "confirmed", "refuted", "inconclusive"):
        errs.append(f"verdict {binding.get('verdict')!r} outside the enum")
    return errs


# R19/R20: documentation arithmetic and chronology
def r_count_drift(state: dict) -> list[str]:
    claimed = re.search(r"# (\d+) checks", state["readme"])
    if claimed and int(claimed.group(1)) != state["report_len"]:
        return [f"README claims {claimed.group(1)} checks, validator runs {state['report_len']}"]
    return []


def _count_state() -> dict:
    return {"readme": _read("README.md"), "report_len": len(V.validate_all(ROOT))}


def r_historical_figures(state: str) -> list[str]:
    chron = state.split("## Declared controls")[0]
    return ["historical entry quotes live counts"] if re.search(
        r"\d+ tests passing and \d+ checks green", chron) else []


def _spelling_state() -> dict:
    """Inline code and fenced blocks are excluded: quoting a banned variant to document it
    is not using it."""
    hits = []
    for f in ROOT.rglob("*.md"):
        if ".git" in f.parts:
            continue
        text = f.read_text()
        text = re.sub(r"```.*?```", "", text, flags=re.S)
        text = re.sub(r"`[^`]*`", "", text)
        for w in ("licence", "behaviour", "judgement"):
            if re.search(rf"\b{w}\b", text, re.I):
                hits.append(f"{f.relative_to(ROOT)}: {w}")
    return {"hits": hits}


def r_spelling_drift(state: dict) -> list[str]:
    return list(state["hits"])


# --- hostile peer defects -------------------------------------------------------

sys.path.insert(0, str(ROOT))  # the harness package lives at the repo root
from harness.untrusted_peer import protocol as UP  # noqa: E402
from harness.untrusted_peer.audit import attack as _attack  # noqa: E402
from harness.untrusted_peer.hardened import HardenedListener as _Hard  # noqa: E402
from harness.untrusted_peer.naive import NaiveListener as _Naive  # noqa: E402
from harness.untrusted_peer.peer import ScriptedPeer as _Peer  # noqa: E402

_GOOD = {"type": "observation", "seq": 1, "note": "ok"}


# --- deception layer -------------------------------------------------------------

import os  # noqa: E402

from harness.deception import Issuance, watermark  # noqa: E402
from harness.deception.alerts import CanaryLedger  # noqa: E402
from harness.deception.credentials import CredentialRegistry  # noqa: E402
from harness.deception.shell import SimulatedShell  # noqa: E402
from harness.deception.vault import EscapedRoot, FakeTree  # noqa: E402


def _dec(kind: str):
    """True = the naive past, which must show the defect; False = the shipped code."""

    def check(naive: bool) -> list[str]:
        issuance = Issuance.create("camp-x", "IS-9001")
        registry, tree = CredentialRegistry(), FakeTree(issuance)
        shell = SimulatedShell(issuance, registry, tree)
        ledger = CanaryLedger(registry)
        ledger.issue(issuance)

        if kind == "traversal":
            import posixpath
            path = "/../../etc/passwd"
            if naive:
                norm = posixpath.normpath("/" + path.lstrip("/"))
                return [] if norm != "/etc/passwd" else ["defect reproduced: /etc/passwd served"]
            try:
                tree.read(path)
            except EscapedRoot:
                return []
            return ["hardened tree served a traversal path"]

        if kind == "env_leak":
            os.environ["AWS_SECRET_ACCESS_KEY"] = "REAL-SECRET-VALUE"
            try:
                out = os.environ["AWS_SECRET_ACCESS_KEY"] if naive else shell.run("env")["stdout"]
                leaked = "REAL-SECRET-VALUE" in out
                if naive:
                    return ["defect reproduced: the listener's own secret reached output"] if leaked else []
                return [] if not leaked else ["hardened env leaked the listener environment"]
            finally:
                os.environ.pop("AWS_SECRET_ACCESS_KEY", None)

        if kind == "shared_credential":
            second = Issuance.create("camp-x", "IS-9002")
            if naive:
                # one value issued for both, so a leak cannot say which place leaked it
                shared = {"AKIASHAREDVALUE123"}
                return [] if len(shared) > 1 else [
                    "defect reproduced: two issuances, one value, no way to attribute the leak"
                ]
            owner = registry.attribute(registry.aws_like(second))
            if owner is None or owner.issuance_id != "IS-9002":
                return [f"value attributed to {getattr(owner, 'issuance_id', None)}"]
            return []

        if kind == "mark_strippable":
            body = tree.read("/srv/app/README.internal.md")
            scrubbed = body.replace("\u200b", "").replace("\u200c", "")
            kept = watermark.attribute(scrubbed)
            if naive:
                return [] if not kept else ["defect reproduced: scrubbing zero-width killed attribution"]
            return [] if kept else ["the visible mark did not survive scrubbing"]

        if kind == "canary_silent":
            transcript = shell.run("env")["stdout"]
            if naive:
                unwatched = CanaryLedger(CredentialRegistry())  # nothing registered, nothing watching
                return [] if unwatched.scan(transcript) else [
                    "defect reproduced: reuse of an artifact raised no alert"
                ]
            first, second = ledger.scan(transcript), ledger.scan(transcript)
            return [] if first and not second else ["the canary did not fire exactly once"]

        if kind == "shell_exec":
            if naive:
                def executing_stub(line: str) -> dict:
                    """Stands in for `subprocess.run(line, shell=True)` without running it."""
                    return {"stdout": line + "\n", "stderr": "", "exit": 0, "issuance_id": "naive"}
                result = executing_stub("rm -rf / --no-preserve-root")
                return ["defect reproduced: the peer's string reached a shell"] if result["exit"] == 0 else []
            result = shell.run("rm -rf / --no-preserve-root")
            return [] if result["exit"] == 127 and not result["stdout"] else ["an unknown command was answered"]

        return [f"unknown deception repro {kind}"]

    return check


def _naive_flag() -> bool:
    return True


def _hardened_flag() -> bool:
    return False


def _peer_guard(kind: str, expected: str | None = None, neutralized=None):
    """historical = the naive listener, current = the hardened one.

    The check receives a listener and runs one hostile peer against it. Errors mean the
    listener failed to defend, which is exactly what the historical state must show and
    the current state must not.
    """
    def check(listener):
        from harness.untrusted_peer.audit import _script_for  # local to avoid a cycle
        now = {"t": 0.0}
        clock = lambda: now["t"]  # noqa: E731
        if kind == "slow_trickle":
            class Trickle(_Peer):
                def read_exact(self, n, deadline=None):
                    now["t"] += 3.0
                    return super().read_exact(n, deadline)
            peer = Trickle(_script_for(kind), clock=clock, timeout_after=1.0)
        else:
            peer = _Peer(_script_for(kind), clock=clock, timeout_after=1.0)
        try:
            msg = listener.read_one(peer)
            outcome = ("accepted", msg)
        except Exception as exc:
            outcome = (type(exc).__name__, exc)

        defended = False
        if expected is not None and outcome[0] == "ProtocolError" and expected in str(outcome[1]):
            defended = True
        if neutralized is not None and outcome[0] == "accepted" and neutralized(outcome[1]):
            defended = True

        if isinstance(listener, _Hard):
            return [] if defended else [f"hardened listener accepted the hostile frame ({outcome[0]})"]
        # Non-empty here means "the defect reproduced", which is what the historical
        # side of the pair is required to show.
        if defended:
            return ["naive listener defended itself, so nothing reproduces"]
        return [f"defect reproduced: {outcome[0]} with no defense in place"]
    return check


def _naive():
    return _Naive(log=lambda _: None)


def _hard():
    return _Hard(clock=lambda: 0.0)  # replaced per-call for trickle in _peer_guard


def _write_tmp(text: str) -> str:
    tmp = Path(tempfile.mkdtemp()) / "injected.md"
    tmp.write_text(text + "\n")
    return str(tmp)


def _promote_locator(claims: dict) -> dict:
    """Status flipped to verified while the section stayed unresolved.

    A genuinely invented section (unresolved -> 'Section 4.2') is an admitted blind spot,
    recorded as such in 08; this repro covers the case the guard exists for."""
    c = copy.deepcopy(claims)
    for cl in c["claims"]:
        if cl.get("locator_status") == "unavailable":
            cl["locator_status"] = "verified"
            break
    return c


def _check_pilot_arithmetic(state: dict) -> list[str]:
    """A pilot below the stratification floor cannot support a per-family number."""
    per_family = state["samples"] / state["families"] * state["prevalence"]
    if state["floor"] is None:
        return [f"no floor set: {per_family:.2f} expected positives per family at "
                f"n={state['samples']}, 14 families, {state['prevalence']:.0%} prevalence"]
    if per_family < state["floor"]:
        return [f"pilot holds {per_family:.2f} expected positives per family, floor is {state['floor']}"]
    return []


# R21/R22/R23: the three previously stated gaps
def r_licence_scope(state):
    if isinstance(state, str):
        return V.check_licence_scope([_write_tmp(state)])
    return V.check_licence_scope(V._tracked_files(ROOT))


def _witness_claims():
    return CLAIMS, _all_retrievals()


def r_locator_witness(state):  # noqa: D401
    claims, retrievals = state
    return V.check_locator_witness(claims, retrievals)


def _witness_stripped():
    c = copy.deepcopy(CLAIMS)
    for cl in c["claims"]:
        if cl["locator_status"] == "verified":
            cl["locator"].pop("witness", None)
            break
    return (c, _all_retrievals())


def _as_payload(flat: dict) -> dict:
    return {
        "required_status_checks": {"contexts": [flat["required_context"]], "strict": flat["strict"]},
        "enforce_admins": {"enabled": flat["enforce_admins"]},
        "allow_force_pushes": {"enabled": flat["allow_force_pushes"]},
        "allow_deletions": {"enabled": flat["allow_deletions"]},
    }


def r_live_protection(state):
    return CP.compare(state["required"], CP.normalize(state["payload"]))


def _live_historical():
    policy = CP.load_expected()
    flat = dict(policy["recorded"], enforce_admins=False)
    return {"required": policy["required"], "payload": _as_payload(flat)}


def _live_current():
    policy = CP.load_expected()
    return {"required": policy["required"], "payload": _as_payload(policy["recorded"])}


# --- review findings on PR #11 --------------------------------------------------

import json as _json  # noqa: E402


def _all_retrievals() -> dict:
    merged = {"retrievals": {}}
    for path in sorted((ROOT / "harness/retrievals").glob("*.json")):
        merged["retrievals"].update(_json.load(open(path)).get("retrievals", {}))
    return merged


def _meta() -> dict:
    return _json.load(open(ROOT / "corpus/out/research-metadata.json"))


def _claims() -> dict:
    return _json.load(open(ROOT / "corpus/out/claims.json"))


def _foreign_witness(claims: dict) -> list[str]:
    meta = _meta()
    retrievals = _all_retrievals()
    claim = next(c for c in claims["claims"] if c["claim_id"] == "D7-C01")
    foreign = next(r for r, rec in retrievals["retrievals"].items() if rec["document_id"] == "D3")
    claim["locator"]["witness"]["retrieval_id"] = foreign
    return V.check_locator_witness(claims, retrievals, meta)


def _clean_witness_check() -> list[str]:
    return V.check_locator_witness(_claims(), _all_retrievals(), _meta())


def _rejection_state(rejections: dict) -> list[str]:
    return V.check_rejected_sources({"rejected_sources": rejections})


def _bad_rejection(**over) -> dict:
    base = {
        "source_id": "RSX",
        "url": "https://example.org/paper",
        "reason_code": "unretrievable",
        "retrieval_attempts": [{"url": "https://example.org/paper", "status": 403}],
        "evidence": "Two requests returned 403 from the origin, so the page was never read.",
    }
    base.update(over)
    return base


def _loaded_manifests(names: list[str]) -> list[str]:
    """A witness citing a document whose manifest was never loaded is an unknown retrieval."""
    retrievals = {"retrievals": {}}
    for name in names:
        retrievals["retrievals"].update(
            _json.load(open(ROOT / "harness/retrievals" / name)).get("retrievals", {})
        )
    return V.check_locator_witness(_claims(), retrievals, _meta())


def _r18_state(text: str) -> list[str]:
    return [] if "(`licence`/`license`," in text else ["the R18 record no longer names two spellings"]


REGISTRY: list[Repro] = [
    Repro("R01", "D3 acceptance status asserted without its basis",
          "a README line claiming TOSEM acceptance",
          lambda st: V.check_status_language([st]),
          lambda: _write_tmp("D1 is Accepted at TOSEM, so the finding is settled."),
          lambda: str(ROOT / "README.md")),
    Repro("R02", "peer-review tiers collapsed into a stronger tier",
          "D3 promoted to publisher_confirmed",
          V.check_peer_review_tiers,
          lambda: _mutated_meta(lambda m: m["documents"][2].__setitem__("peer_review_tier", "publisher_confirmed")),
          lambda: META),
    Repro("R03", "non-permissive source moved into the redistributable partition",
          "D1 added to redistributable while non-permissive",
          V.check_license_consistency,
          lambda: _mutated_meta(lambda m: (m["corpus_level_observations"]["redistributable"].append("D1"),
                                           m["corpus_level_observations"]["non_redistributable"].remove("D1"))),
          lambda: META),
    Repro("R04", "schema_version declared with nothing validating it",
          "a document stripped of its reproducibility block",
          lambda st: V.schema_errors(st, json.loads(_read("schemas/research-metadata.schema.json"))),
          lambda: _mutated_meta(lambda m: m["documents"][0].pop("reproducibility")),
          lambda: META),
    Repro("R05", "unavailable locator relabelled verified",
          "a claim re-pointed at a section never retrieved",
          V.check_locator_resolution,
          lambda: _promote_locator(CLAIMS),
          lambda: CLAIMS),
    Repro("R06", "replication claimed without a replication record",
          "claim marked independently replicated",
          lambda st: V.check_replication_claims(st, META),
          lambda: _mutated_claims(lambda c: c["claims"][0].__setitem__("replication_status", "independent")),
          lambda: CLAIMS),
    Repro("R07", "corpus totals inflated past the source count",
          "coverage raised to 9 verified of 5 documents",
          V.check_corpus_counts,
          lambda: _mutated_meta(lambda m: m["corpus_level_observations"].__setitem__("documents_verified", 9)),
          lambda: META),
    Repro("R08", "verification smuggled into an extension field",
          "verified: true added to a document",
          V.check_extension_keys,
          lambda: _mutated_meta(lambda m: m["documents"][0].__setitem__("verified", True)),
          lambda: META),
    Repro("R09", "CI workflow outside the paths Actions reads",
          "workflow misplaced and dev requirements ignored",
          r_workflow_location,
          lambda: {"workflow_at_expected_path": False, "requirements_ignored": True,
                   "requirements_tracked": False},
          _workflow_state),
    Repro("R10", "required status context named as the workflow",
          "README naming validate as the required check",
          r_required_context_name,
          lambda: {"workflow_name": "validate", "job_name": "corpus",
                   "readme": "pull requests are required, the `validate` job must pass"},
          _context_state),
    Repro("R11", "protection bypassable by the account pushing",
          "enforce_admins off, so the admin push succeeded",
          r_protection_bypass,
          lambda: {"required": {"required_context": "corpus", "strict": True, "enforce_admins": True,
                                "allow_force_pushes": False, "allow_deletions": False},
                   "observed": {"required_context": "corpus", "strict": True, "enforce_admins": False,
                                "allow_force_pushes": False, "allow_deletions": False}},
          _protection_state),
    Repro("R12", "pilot size incompatible with per-CWE stratification",
          "100 samples across 14 families, no floor, versus a pooled stage-1 run",
          _check_pilot_arithmetic,
          lambda: {"samples": 100, "families": 14, "prevalence": 0.10, "floor": None},
          lambda: {"samples": 100, "families": 1, "prevalence": 0.10, "floor": 5}),
    Repro("R13", "no requirement to emit a verdict per sample",
          "S6 as it was, scoring findings rather than verdicts",
          r_verdicts_required,
          lambda: "For each reviewer pair, compute the phi coefficient over per-sample binary error vectors.",
          lambda: _read("corpus/out/02-engineering-translation.md")),
    Repro("R14", "fabrication rate measured after the gate that suppresses it",
          "S4 counting only shipped findings",
          r_fabrication_circular,
          lambda: "Fabrication rate, defined as shipped findings that a maintainer rejects as non-reproducing.",
          lambda: _read("corpus/out/02-engineering-translation.md")),
    Repro("R15", "human review listed as an executable oracle",
          "oracle_binding including manual-review",
          r_oracle_manual_review,
          lambda: '  "oracle_binding": "semgrep-rule | unit-test | manual-review | none",\n',
          lambda: _read("corpus/out/05-absurdity-lane.md")),
    Repro("R16", "oracle verdict recorded with no identity",
          "oracle_binding as an unversioned string",
          r_oracle_identity,
          lambda: '```json\n{"id": "H-0007", "oracle_binding": "semgrep-rule", "status": "hypothesis"}\n```\n',
          lambda: _read("corpus/out/05-absurdity-lane.md")),
    Repro("R17", "status lint that could not see JSON",
          "peer_review_status asserting review, unqualified",
          V.check_status_fields,
          lambda: _mutated_meta(lambda m: m["documents"][3].__setitem__("peer_review_status", "peer reviewed, ESORICS 2024")),
          lambda: META),
    Repro("R18", "two spellings of one concept in one repository",
          "licence / behaviour / judgement variants",
          r_spelling_drift,
          lambda: {"hits": ["README.md: licence", "README.md: behaviour"]},
          _spelling_state),
    Repro("R19", "documented counts drifting from reality",
          "README claiming 13 checks while 14 run",
          r_count_drift,
          lambda: {"readme": "python tools/validate_corpus.py   # 13 checks", "report_len": 14},
          _count_state),
    Repro("R20", "historical entry quoting present-day figures",
          "chronology entry stating live counts as then",
          r_historical_figures,
          lambda: "## Chronology\nThe content was tested, 50 tests passing and 14 checks green, and that is why.",
          lambda: _read("README.md")),
    Repro("R21", "copyleft scope asserted beyond adapted material as fact",
          "the withdrawn sentence, reinstated in a corpus note",
          r_licence_scope,
          lambda: "A compilation incorporating CC BY-SA material must itself be licensed CC BY-SA.",
          lambda: "checked in place"),
    Repro("R22", "verified locator with no verbatim witness",
          "a plausible section number and nothing behind it",
          r_locator_witness,
          _witness_stripped,
          _witness_claims),
    Repro("R23", "protection snapshot that cannot notice a setting loosened later",
          "live payload with enforce_admins back on for the pushing account",
          r_live_protection,
          _live_historical,
          _live_current),
    Repro("R24", "peer's declared frame length is allocated before it is read",
          "a 4-byte header claiming 2 GB",
          _peer_guard("declared_length", expected="frame_too_large"), _naive, _hard),
    Repro("R25", "malformed bytes from the peer kill the receiving loop",
          "invalid UTF-8 inside a well-formed frame",
          _peer_guard("malformed_bytes", expected="not_utf8"), _naive, _hard),
    Repro("R26", "the peer's own claim to a privileged role is believed",
          "a frame carrying role=operator",
          _peer_guard("forged_role", neutralized=lambda m: m["role"] == "peer"), _naive, _hard),
    Repro("R27", "peer text is written to the log without sanitizing",
          "an ANSI clear-screen plus a forged log line",
          _peer_guard("log_injection", neutralized=lambda m: "\x1b" not in m["note"]), _naive, _hard),
    Repro("R28", "an unrecognized field is accepted and carried into logic",
          "a frame carrying cmd=shutdown",
          _peer_guard("unknown_field", expected="unknown_field"), _naive, _hard),
    Repro("R29", "nothing bounds how long a peer may take to send one frame",
          "a trickle costing three seconds per read",
          _peer_guard("slow_trickle", expected="deadline_exceeded"), _naive, _hard),
    Repro("R30", "path traversal served a host file after being normalized first",
          "a lookup of /../../etc/passwd", _dec("traversal"), _naive_flag, _hardened_flag),
    Repro("R31", "command output could carry the listener's own environment",
          "an env request beside a real AWS secret", _dec("env_leak"), _naive_flag, _hardened_flag),
    Repro("R32", "one shared credential made a leak unattributable",
          "two issuances, one value", _dec("shared_credential"), _naive_flag, _hardened_flag),
    Repro("R33", "the watermark died as soon as invisible characters were scrubbed",
          "zero-width removal before exfiltration", _dec("mark_strippable"), _naive_flag, _hardened_flag),
    Repro("R34", "a canary nobody watched: reuse raised nothing",
          "the same transcript scanned twice", _dec("canary_silent"), _naive_flag, _hardened_flag),
    Repro("R35", "the peer's command string reached a shell",
          "rm -rf / against the simulated shell", _dec("shell_exec"), _naive_flag, _hardened_flag),
    Repro("R36", "a witness could cite a retrieval belonging to a different document",
          "a D7 claim pointing at a valid D3 retrieval",
          lambda errors: errors,
          lambda: _foreign_witness(_claims()),
          lambda: _clean_witness_check()),
    Repro("R37", "a rejection could be evidenced by fetching an unrelated URL",
          "one attempt at https://unrelated.test/x",
          _rejection_state,
          lambda: [_bad_rejection(retrieval_attempts=[{"url": "https://unrelated.test/x", "status": 403}])],
          lambda: _meta().get("rejected_sources", [])),
    Repro("R38", "a rejection could cite a status outside the HTTP range",
          "status 999 recorded as the attempt",
          _rejection_state,
          lambda: [_bad_rejection(retrieval_attempts=[{"url": "https://example.org/paper", "status": 999}])],
          lambda: _meta().get("rejected_sources", [])),
    Repro("R39", "a URL check that was a prefix test, so https:// alone passed",
          "the string https:// offered as a source URL",
          lambda url: [e] if (e := V.url_structure_error(url)) else [],
          lambda: "https://",
          lambda: _meta()["documents"][-1]["source_url"]),
    Repro("R40", "retrieval manifests were loaded by hardcoded filename, so a new one never registered",
          "only D3.json loaded while D7 claims cite D7 retrievals",
          _loaded_manifests, lambda: ["D3.json"], lambda: ["D3.json", "D6.json", "D7.json"]),
    Repro("R41", "a global rename rewrote the historical R18 record it was meant to document",
          "the row reduced to `license`/`license`",
          _r18_state,
          lambda: "| R18 | one concept spelled two ways (`license`/`license`) | x |",
          lambda: (ROOT / "CHANGELOG.md").read_text()),
]


BY_ID = {r.id: r for r in REGISTRY}


def main(argv: list[str]) -> int:
    if "--list" in argv or not argv:
        for r in REGISTRY:
            print(f"{r.id}  {r.defect}\n      reconstructs: {r.reconstructs}")
        return 0
    if "--check" in argv:
        failed = []
        for r in REGISTRY:
            hist = r.run(r.historical())
            now = r.run(r.current())
            if not hist:
                status, why = "ESCAPED", "defect not reproduced on the historical state"
            elif now:
                status, why = "REGRESSED", f"guard fires on the current tree: {now[0]}"
            else:
                status, why = "CAUGHT", "reproduced, then caught"
            print(f"[{status:8}] {r.id} {r.defect}  ({why})")
            if status != "CAUGHT":
                failed.append(r.id)
        print(f"\n{len(REGISTRY) - len(failed)}/{len(REGISTRY)} reproduced and caught")
        return 1 if failed else 0
    rid = argv[0]
    if rid not in BY_ID:
        print(f"unknown repro {rid!r}; try --list", file=sys.stderr)
        return 2
    r = BY_ID[rid]
    hist, now = r.run(r.historical()), r.run(r.current())
    print(f"{rid}: {r.defect}")
    print(f"reconstructs: {r.reconstructs}")
    print("on the historical state:")
    for e in hist or ["<nothing: the defect does not reproduce>" ]:
        print(f"  - {e}")
    print("on the current tree:")
    for e in now or ["<clean>"]:
        print(f"  - {e}")
    return 0 if hist and not now else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
