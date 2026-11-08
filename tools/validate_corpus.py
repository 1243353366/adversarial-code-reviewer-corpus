#!/usr/bin/env python3
"""Validate the corpus: schema conformance, referential integrity and evidence gates.

Design note: JSON validity is not schema validity. Every check here exists because a
specific failure was observed in review, not as generic hygiene.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "corpus" / "out" / "research-metadata.json"
CLAIMS = ROOT / "corpus" / "out" / "claims.json"
METADATA_SCHEMA = ROOT / "schemas" / "research-metadata.schema.json"
CLAIM_SCHEMA = ROOT / "schemas" / "claim.schema.json"

ARXIV_IN_URL = re.compile(r"^https://arxiv\.org/abs/([0-9]{4}\.[0-9]{4,5})$")
# Document bodies are forbidden anywhere; plain-text and HTML are only forbidden
# inside the corpus tree, so build files like requirements-dev.txt remain legal.
FORBIDDEN_BODY_SUFFIXES = (".pdf", ".epub", ".docx")
CORPUS_SCOPED_SUFFIXES = (".txt", ".html", ".htm")
MAX_PUBLIC_ARTIFACT_BYTES = 512_000


def load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def schema_errors(instance, schema: dict) -> list[str]:
    """Return a list of human-readable schema violations (empty when valid)."""
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - exercised only without the dev extra
        return ["jsonschema is not installed; run: pip install -r requirements-dev.txt"]
    validator = jsonschema.Draft202012Validator(schema)
    out = []
    for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"{where}: {err.message}")
    return out


def check_unique_doc_ids(meta: dict) -> list[str]:
    seen, dupes = set(), set()
    for doc in meta.get("documents", []):
        did = doc.get("doc_id")
        if did in seen:
            dupes.add(did)
        seen.add(did)
    return [f"duplicate doc_id: {d}" for d in sorted(dupes)]


def check_arxiv_url_consistency(meta: dict) -> list[str]:
    errors = []
    for doc in meta.get("documents", []):
        did = doc.get("doc_id", "?")
        url = doc.get("source_url", "")
        arxiv_id = doc.get("arxiv_id")
        if arxiv_id:
            match = ARXIV_IN_URL.match(url)
            if not match:
                errors.append(f"{did}: arxiv_id set but source_url is not a canonical arXiv abs URL: {url!r}")
            elif match.group(1) != arxiv_id:
                errors.append(
                    f"{did}: arxiv_id {arxiv_id!r} does not match source_url {url!r}"
                )
        else:
            # non-arXiv sources must still resolve to a real https URL, and must not
            # masquerade as arXiv records
            if not url.startswith("https://"):
                errors.append(f"{did}: source_url must be https: {url!r}")
            if "arxiv.org" in url:
                errors.append(f"{did}: source_url points at arXiv but arxiv_id is null")
    return errors


def check_peer_review_tiers(meta: dict) -> list[str]:
    """Each document's tier must appear in the corpus-level roll-up, and only there."""
    errors: list[str] = []
    tiers = meta.get("corpus_level_observations", {}).get("peer_review_tiers", {})
    buckets = {
        key: set(tiers.get(key, []))
        for key in ("publisher_confirmed", "manuscript_asserted", "secondary_source", "unreviewed")
    }
    declared = {did: key for key, ids in buckets.items() for did in ids}
    for doc in meta.get("documents", []):
        did, tier = doc.get("doc_id"), doc.get("peer_review_tier")
        if tier not in buckets:
            errors.append(f"{did}: unknown peer_review_tier {tier!r}")
            continue
        if declared.get(did) != tier:
            errors.append(
                f"{did}: document tier {tier!r} disagrees with corpus-level roll-up "
                f"({declared.get(did)!r})"
            )
        if tier != "unreviewed" and len(doc.get("peer_review_tier_basis", "")) < 10:
            errors.append(f"{did}: non-unreviewed tier requires a stated basis")
    for did in declared:
        if did not in {d.get("doc_id") for d in meta.get("documents", [])}:
            errors.append(f"corpus-level roll-up references unknown document {did}")
    return errors


def check_no_document_bodies(paths: list[str]) -> list[str]:
    """Licensing guard: four of five sources permit no redistribution."""
    errors = []
    for raw in paths:
        path = Path(raw)
        if any(part in {"node_modules", ".git"} for part in path.parts):
            continue
        suffix = path.suffix.lower()
        in_corpus = "corpus" in path.parts
        if suffix in FORBIDDEN_BODY_SUFFIXES or (suffix in CORPUS_SCOPED_SUFFIXES and in_corpus):
            errors.append(f"document body tracked in repository: {path}")
        elif path.exists() and path.stat().st_size > MAX_PUBLIC_ARTIFACT_BYTES:
            errors.append(f"tracked file exceeds {MAX_PUBLIC_ARTIFACT_BYTES} bytes: {path}")
    return errors


def check_claim_gate(claims_doc: dict, known_doc_ids: set[str]) -> list[str]:
    """A claim may only be consumed as a security rule when it is locator-verified."""
    errors = []
    seen = set()
    for claim in claims_doc.get("claims", []):
        cid = claim.get("claim_id", "?")
        if cid in seen:
            errors.append(f"{cid}: duplicate claim_id")
        seen.add(cid)
        if claim.get("document_id") not in known_doc_ids:
            errors.append(f"{cid}: document_id {claim.get('document_id')!r} not in metadata")
        uses = claim.get("permitted_downstream_uses", [])
        if "security_rule" in uses:
            if claim.get("verification_status") != "verified_against_source":
                errors.append(f"{cid}: security_rule use requires verified_against_source")
            if claim.get("locator_status") != "verified":
                errors.append(f"{cid}: security_rule use requires a verified locator")
            if claim.get("evidence_type") in {"author_interpretation", "derived_inference"}:
                errors.append(
                    f"{cid}: security_rule use may not rest on {claim.get('evidence_type')}"
                )
        if claim.get("locator_status") == "verified" and (
            claim.get("verification_status") != "verified_against_source"
        ):
            errors.append(f"{cid}: locator marked verified but claim is not verified")
    return errors


# --- checks added after an adversarial pass on the validators themselves ------

ASSERTIVE_STATUS = (
    "accepted at",
    "accepted tosEm".lower(),
    "accepted for publication",
    "published in acm",
    "peer-reviewed publication",
    "peer reviewed and published",
)
STATUS_QUALIFIERS = (
    "per manuscript",
    "asserted",
    "unconfirmed",
    "not confirmed",
    "secondary",
    "tier",
    "claims",
    "as stated",
)
PERMISSIVE_LICENSE = re.compile(r"(CC BY|CC0|MIT|Apache|BSD)", re.I)


def check_status_language(paths: list[str]) -> list[str]:
    """A markdown claim of publication must carry its qualifier on the same line.

    The defect this prevents was observed: a README said "Accepted TOSEM" while the
    provenance report recorded that no publisher record had been opened.
    """
    errors = []
    for raw in paths:
        path = Path(raw)
        if path.suffix.lower() != ".md" or not path.exists():
            continue
        in_fence = False
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            # A quoted example inside backticks is documentation, not a claim. This check
            # has now produced two false positives, both from quoting what it hunts.
            low = re.sub(r"`[^`]*`", "", line).lower()
            hit = next((p for p in ASSERTIVE_STATUS if p in low), None)
            if not hit:
                continue
            pos = low.index(hit)
            window = low[max(0, pos - 30):pos]
            # A negation is the opposite of the thing this check exists to catch.
            if re.search(r"\b(not|never|no|neither|isn't|wasn't)\b", window):
                continue
            if not any(q in low for q in STATUS_QUALIFIERS):
                errors.append(
                    f"{path}:{lineno}: unqualified publication claim {hit!r} "
                    f"(add the basis on the same line)"
                )
    return errors


def check_corpus_counts(meta: dict) -> list[str]:
    """Corpus-level totals must reconcile with the document list, not be typed by hand."""
    errors = []
    obs = meta.get("corpus_level_observations", {})
    docs = meta.get("documents", [])
    ids = [d.get("doc_id") for d in docs]
    all_ids = set(ids)

    verified = obs.get("documents_verified")
    unverifiable = obs.get("documents_unverifiable")
    if isinstance(verified, int) and isinstance(unverifiable, int):
        if verified + unverifiable != len(docs):
            errors.append(
                f"corpus counts do not reconcile: verified {verified} + unverifiable "
                f"{unverifiable} != {len(docs)} documents"
            )

    preprints = set(obs.get("preprints", []))
    if not preprints <= all_ids:
        errors.append(f"preprints references unknown documents: {sorted(preprints - all_ids)}")

    redistributable = set(obs.get("redistributable", []))
    non_redistributable = set(obs.get("non_redistributable", []))
    if redistributable & non_redistributable:
        errors.append(
            f"documents listed both redistributable and not: "
            f"{sorted(redistributable & non_redistributable)}"
        )
    if redistributable | non_redistributable != all_ids:
        missing = all_ids - (redistributable | non_redistributable)
        extra = (redistributable | non_redistributable) - all_ids
        if missing:
            errors.append(f"documents missing from the redistribution partition: {sorted(missing)}")
        if extra:
            errors.append(f"redistribution partition lists unknown documents: {sorted(extra)}")
    return errors


def check_license_consistency(meta: dict) -> list[str]:
    """The redistribution partition must agree with each document's license field."""
    errors = []
    obs = meta.get("corpus_level_observations", {})
    redistributable = set(obs.get("redistributable", []))
    for doc in meta.get("documents", []):
        did = doc.get("doc_id")
        permissive = bool(PERMISSIVE_LICENSE.search(doc.get("license", "")))
        if did in redistributable and not permissive:
            errors.append(
                f"{did}: listed redistributable but license {doc.get('license')!r} is not permissive"
            )
        if did not in redistributable and permissive:
            errors.append(
                f"{did}: permissive license {doc.get('license')!r} but listed as non-redistributable"
            )
    return errors


def check_replication_claims(claims_doc: dict, meta: dict) -> list[str]:
    """A claim cannot assert replication the document does not record."""
    errors = []
    replicated = {
        d.get("doc_id")
        for d in meta.get("documents", [])
        if d.get("reproducibility", {}).get("independently_replicated") is True
    }
    for claim in claims_doc.get("claims", []):
        if claim.get("replication_status") != "none" and claim.get("document_id") not in replicated:
            errors.append(
                f"{claim.get('claim_id')}: replication_status "
                f"{claim.get('replication_status')!r} but {claim.get('document_id')} records no "
                f"independent replication"
            )
    return errors


def check_locator_resolution(claims_doc: dict) -> list[str]:
    """A locator claiming to exist must name a real section."""
    errors = []
    for claim in claims_doc.get("claims", []):
        status = claim.get("locator_status")
        section = claim.get("locator", {}).get("section", "")
        if status == "unavailable":
            continue
        if section.strip().lower() in {"", "unresolved", "unknown", "tbd", "n/a"}:
            errors.append(
                f"{claim.get('claim_id')}: locator_status {status!r} but section is {section!r}"
            )
    return errors


def check_extension_keys(meta: dict) -> list[str]:
    """Unknown document fields must be namespaced, so an adversary cannot smuggle `verified: true`."""
    errors = []
    schema = load(ROOT / "schemas" / "research-metadata.schema.json")
    allowed = set(schema["$defs"]["document"].get("properties", {}))
    for doc in meta.get("documents", []):
        for key in doc:
            if key not in allowed and not key.startswith("x_"):
                errors.append(
                    f"{doc.get('doc_id')}: undocumented field {key!r} (prefix with x_ to extend)"
                )
    return errors


STATUS_FIELDS = ("peer_review_status", "doi_status", "retraction_or_correction_status")
NEGATION = re.compile(r"\b(not|never|no|neither|isn't|wasn't)\b")
EXPECTED_TIER = {
    "manuscript_asserted": ("manuscript", "asserted", "header"),
    "secondary_source": ("secondary", "citations", "not opened", "per "),
}


def _unqualified_claim(text: str) -> str | None:
    """Return the assertive phrase in `text` if nothing on the string qualifies it."""
    low = text.lower()
    hit = next((p for p in ASSERTIVE_STATUS if p in low), None)
    if not hit:
        return None
    window = low[max(0, low.index(hit) - 30):low.index(hit)]
    if NEGATION.search(window):
        return None
    if any(q in low for q in STATUS_QUALIFIERS):
        return None
    return hit


def check_status_fields(meta: dict) -> list[str]:
    """The JSON status fields are free text, and were exempt from the check that scans markdown.

    Two of them asserted peer review with no stated basis while their own tier said the
    basis was a manuscript header or a third party. The markdown lint could not see them.
    """
    errors = []
    for doc in meta.get("documents", []):
        did = doc.get("doc_id")
        tier = doc.get("peer_review_tier")
        for field in STATUS_FIELDS:
            text = doc.get(field)
            if not isinstance(text, str):
                continue
            hit = _unqualified_claim(text)
            if hit:
                errors.append(
                    f"{did}.{field}: unqualified claim {hit!r} in {text[:60]!r}"
                )
        text = (doc.get("peer_review_status") or "").lower()
        if tier in EXPECTED_TIER and text:
            if not any(tok in text for tok in EXPECTED_TIER[tier]):
                errors.append(
                    f"{did}.peer_review_status: tier {tier!r} but no basis stated in "
                    f"{text[:60]!r}"
                )
    return errors


COPYLEFT = re.compile(r"\b(CC BY-SA|BY-SA|ShareAlike|share-alike|copyleft|AGPL|GPL-3)\b", re.I)
SCOPE_EXPANSION = re.compile(
    r"(whole|entire|any)\s+(compilation|collection|repository|package)"
    r"|must\s+(itself\s+)?(be\s+)?licen[cs]ed"
    r"|inherits?\s+the\s+licen[cs]e"
    r"|licen[cs]e\s+(propagates|extends)\s+to",
    re.I,
)
WITHDRAWN = re.compile(
    r"\b(not|never|no|wrong|withdrawn|overstated|too broad|does not|need not|exception|"
    r"misreading|cannot)\b",
    re.I,
)


def check_licence_scope(paths: list[str]) -> list[str]:
    """A ShareAlike claim that reaches beyond adapted material, stated as fact.

    The original defect in this repository was exactly this sentence class: a prose
    assertion that a copyleft license covers the compilation. No structural check caught
    it, so it survived a review whose job was to catch it. Withdrawal lines and quoted
    examples are allowed; an unqualified scope-expansion claim is not.
    """
    errors = []
    for path in paths:
        p = Path(path)
        if p.suffix != ".md":
            continue
        text = p.read_text()
        text = re.sub(r"```.*?```", "", text, flags=re.S)
        text = re.sub(r"`[^`]*`", "", text)
        for lineno, line in enumerate(text.splitlines(), 1):
            if not COPYLEFT.search(line) or not SCOPE_EXPANSION.search(line):
                continue
            if WITHDRAWN.search(line):
                continue
            errors.append(
                f"{p.name}:{lineno}: copyleft scope asserted beyond adapted material: "
                f"{line.strip()[:90]!r}"
            )
    return errors


REJECT_REASONS = {
    "provenance_unestablished", "unretrievable", "licence_forbids",
    "duplicate", "out_of_scope", "superseded",
}


def check_rejected_sources(meta: dict) -> list[str]:
    """A rejection is a claim too: it needs a reason and at least one attempt behind it."""
    errors, seen = [], set()
    for r in meta.get("rejected_sources", []):
        sid = r.get("source_id")
        if sid in seen:
            errors.append(f"{sid}: rejected source listed twice")
        seen.add(sid)
        if r.get("reason_code") not in REJECT_REASONS:
            errors.append(f"{sid}: unknown rejection reason {r.get('reason_code')!r}")
        if not r.get("retrieval_attempts"):
            errors.append(f"{sid}: rejected with no retrieval attempt recorded, so the rejection is unevidenced")
        if len(r.get("evidence", "")) < 40:
            errors.append(f"{sid}: rejection evidence is too thin to check")
    return errors


def check_locator_witness(claims_doc: dict, retrievals: dict) -> list[str]:
    """A verified locator needs a verbatim witness, not just a plausible section number.

    An invented section slides past every existence check; a quote with an offset and an
    artifact hash does not, because a second party can re-fetch and compare. Offline this
    cannot prove the quote exists in the source. It can prove the record is shaped so that
    someone else can.
    """
    errors = []
    known = retrievals.get("retrievals", {})
    for claim in claims_doc.get("claims", []):
        if claim.get("locator_status") != "verified":
            continue
        cid = claim.get("claim_id")
        witness = claim.get("locator", {}).get("witness")
        if not isinstance(witness, dict):
            errors.append(f"{cid}: verified locator has no verbatim witness")
            continue
        quote = (witness.get("quote") or "").strip()
        words = len(quote.split())
        if words < 8:
            errors.append(f"{cid}: witness quote is {words} words; a fragment proves nothing")
        if words > 80:
            errors.append(f"{cid}: witness quote is {words} words; trim to the sentence")
        if witness.get("length") != len(quote):
            errors.append(
                f"{cid}: witness length {witness.get('length')} != quote length {len(quote)}"
            )
        if not isinstance(witness.get("offset"), int) or witness["offset"] < 0:
            errors.append(f"{cid}: witness offset missing or negative")
        rid = witness.get("retrieval_id")
        if rid not in known:
            errors.append(f"{cid}: witness cites unknown retrieval {rid!r}")
        elif not known[rid].get("artifact_sha256"):
            errors.append(f"{cid}: retrieval {rid!r} records no artifact hash")
        claim_text = (claim.get("claim_text") or "").lower()
        if quote and quote.lower() in claim_text:
            errors.append(f"{cid}: witness quote restates the claim instead of the source")
    return errors


def _tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return [str(root / line) for line in out.splitlines() if line.strip()]


def validate_all(root: Path = ROOT) -> dict[str, list[str]]:
    report: dict[str, list[str]] = {}
    meta = load(root / "corpus" / "out" / "research-metadata.json")
    claims_doc = load(root / "corpus" / "out" / "claims.json")
    tracked = _tracked_files(root)

    report["metadata_schema"] = schema_errors(meta, load(root / "schemas" / "research-metadata.schema.json"))
    report["claim_schema"] = schema_errors(claims_doc, load(root / "schemas" / "claim.schema.json"))
    report["doc_ids"] = check_unique_doc_ids(meta)
    report["arxiv_urls"] = check_arxiv_url_consistency(meta)
    report["peer_review_tiers"] = check_peer_review_tiers(meta)
    report["claim_gate"] = check_claim_gate(
        claims_doc, {d.get("doc_id") for d in meta.get("documents", [])}
    )
    report["licensing_guard"] = check_no_document_bodies(tracked)
    report["corpus_counts"] = check_corpus_counts(meta)
    report["license_consistency"] = check_license_consistency(meta)
    report["replication_claims"] = check_replication_claims(claims_doc, meta)
    report["locator_resolution"] = check_locator_resolution(claims_doc)
    report["extension_keys"] = check_extension_keys(meta)
    report["licence_scope"] = check_licence_scope(tracked)
    report["rejected_sources"] = check_rejected_sources(meta)
    report["locator_witness"] = check_locator_witness(
        claims_doc, load(root / "harness/retrievals/D3.json") if (root / "harness/retrievals/D3.json").exists() else {}
    )
    report["status_fields"] = check_status_fields(meta)
    report["status_language"] = check_status_language(tracked)
    return report


def main() -> int:
    report = validate_all()
    failed = False
    for name, errors in report.items():
        status = "PASS" if not errors else f"FAIL ({len(errors)})"
        print(f"[{status:>8}] {name}")
        if errors:
            failed = True
            for err in errors:
                print(f"           - {err}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
