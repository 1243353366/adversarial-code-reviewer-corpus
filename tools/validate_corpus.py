#!/usr/bin/env python3
"""Validate the corpus: schema conformance, referential integrity and evidence gates.

Design note: JSON validity is not schema validity. Every check here exists because a
specific failure was observed in review, not as generic hygiene.
"""
from __future__ import annotations

import json
import re
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
        match = ARXIV_IN_URL.match(url)
        if not match:
            errors.append(f"{did}: source_url is not a canonical arXiv abs URL: {url!r}")
        elif match.group(1) != doc.get("arxiv_id"):
            errors.append(
                f"{did}: arxiv_id {doc.get('arxiv_id')!r} does not match source_url {url!r}"
            )
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


def validate_all(root: Path = ROOT) -> dict[str, list[str]]:
    report: dict[str, list[str]] = {}
    meta = load(root / "corpus" / "out" / "research-metadata.json")
    claims_doc = load(root / "corpus" / "out" / "claims.json")

    report["metadata_schema"] = schema_errors(meta, load(root / "schemas" / "research-metadata.schema.json"))
    report["claim_schema"] = schema_errors(claims_doc, load(root / "schemas" / "claim.schema.json"))
    report["doc_ids"] = check_unique_doc_ids(meta)
    report["arxiv_urls"] = check_arxiv_url_consistency(meta)
    report["peer_review_tiers"] = check_peer_review_tiers(meta)
    report["claim_gate"] = check_claim_gate(
        claims_doc, {d.get("doc_id") for d in meta.get("documents", [])}
    )

    tracked = []
    git_index = root / ".git" / "index"
    if git_index.exists():
        import subprocess

        try:
            out = subprocess.run(
                ["git", "-C", str(root), "ls-files"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            tracked = [str(root / line) for line in out.splitlines() if line.strip()]
        except (OSError, subprocess.CalledProcessError):
            tracked = []
    report["licensing_guard"] = check_no_document_bodies(tracked)
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
