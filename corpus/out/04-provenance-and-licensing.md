# Output 8: Provenance and licensing report

Checked 2026-11-06 against arXiv abstract pages, the arXiv API (`corpus/api.xml`) and retrieved full texts.

---

## 1. Provenance table

| ID | arXiv | Versions | Peer review | DOI status | License | Redistributable |
|---|---|---|---|---|---|---|
| D1 | 2507.22659 | v1 2025-07-30; v2 2025-12-19 | Accepted TOSEM per manuscript header, in press | 10.1145/3815425 asserted in arXiv metadata; manuscript body has placeholder `XXXXXXX.XXXXXXX`; not confirmed at ACM DL | arXiv non-exclusive distribution | No |
| D2 | 2502.07049 | v1 only | CSUR 58(5), Nov 2025, per external citations; publisher record not opened | Unresolved | arXiv non-exclusive distribution | No |
| D3 | 2508.04448 | v1 only | **None.** Preprint; manuscript refers to itself as a thesis | None | CC BY-SA 4.0 | Yes, with conditions |
| D4 | 2408.16400 | v1 only | ESORICS 2024 | Unresolved | arXiv non-exclusive distribution | No |
| D5 | 2404.02525 | v1 2024-04-03; v2 2024-10-07 | TOSEM, May 2025 | Unresolved | arXiv non-exclusive distribution | No |

---

## 2. Licensing: the material constraint

**Four of five documents carry the arXiv perpetual non-exclusive distribution license.** That license grants arXiv the right to distribute. It is **not** a reuse license and it does not permit redistribution of the document by a third party, modified or not.

Consequence for a public repository: you may link, cite, store metadata, and quote short excerpts with attribution. You may not commit the PDFs, the extracted full texts, or substantially reproduced tables and figures into a public repo.

This matters concretely because the working tree for this run contains full-text copies at `corpus/txt_*.txt` and `corpus/html_*.html`. Those must stay local and out of version control, or the public repo is in breach. Add an ignore rule before the first commit.

**D3 is the exception and carries its own trap.** CC BY-SA 4.0 permits redistribution with attribution, but the share-alike term propagates: a compilation that incorporates CC BY-SA material and is distributed publicly must itself be licensed CC BY-SA. Mixing D3's content into a corpus that also carries non-redistributable material creates an unresolvable conflict. Practical policy: keep D3's redistributable excerpts in a clearly separated, separately licensed area, or reduce it to metadata plus citation like the others.

**Recommended corpus policy.**
- Public repo: one record per document containing metadata, locators, a short attributed quotation, and evidence classifications. No document bodies.
- Private store: full texts, hash-pinned to the retrieved version.
- Every record carries a `license` and `redistributable` field, and any export path checks them mechanically rather than by convention.

---

## 3. Peer review and status flags

- **D3 is not peer reviewed.** It is a degree thesis adapted to a preprint, by the manuscript's own wording. Treat its numbers as provisional even though its design is sound.
- **D1's acceptance is asserted, not confirmed.** The manuscript states `Journal: TOSEM` with a placeholder DOI. The arXiv metadata carries a real-looking DOI, which usually indicates an accepted journal version. That is strong evidence but not publisher confirmation.
- **D2 and D5** have venue claims supported by multiple independent citing works, which is good secondary evidence, but the publisher records were not opened and their DOIs remain unresolved.

---

## 4. Withdrawal, correction and retraction

Method used: examined each arXiv abstract page for withdrawal or replacement notices and compared version history. **No withdrawal, correction or retraction notices observed.** This was not checked against Retraction Watch or publisher errata pages, so treat "none observed" as a status, not a clearance.

Two version-level facts that function like corrections and must be pinned:

- **D1 changed its evidence base between versions.** v2 extends the study window to November 2025 and reports 263 studies. A citation to "the SLR" without a version is ambiguous.
- **D5's v2** supersedes its v1 on arXiv. Published TOSEM version may differ from both.

---

## 5. Attribution requirements

- D3 requires attribution under CC BY-SA: cite Gnieciak and Szandala, *Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection*, arXiv:2508.04448, and mark any adaptation as adapted, with the same license.
- The other four require ordinary scholarly citation and no redistribution.
- Any derived claim in a generated report must distinguish source-attributed statement from system inference. This is the protocol's own rule and it is also the practical way to avoid implying endorsement by the cited authors.

---

## 6. Evidence status ledger

Independent replication: **zero of five** documents have an independent replication identified in this pass. "Not independently verified" is therefore the correct status for every extracted finding, including the ones tagged `[E]` above, since `[E]` means "established by this source", not "established".

| Claim | Established by | Replicated | Contradicted |
|---|---|---|---|
| LLMs fail line/column localization on this benchmark | D3 only | No | Not tested elsewhere in this set |
| Models hallucinate stale-dependency findings | D3 only | No | Not tested elsewhere |
| Benchmark datasets contain mislabels in both directions | D4 only | No | Indirectly consistent with D1, D5 |
| Fine-tuning gains do not transfer across benchmarks | D4 only | No | In tension with D2 (C1) |
| Data leakage inflates benchmark metrics | D1, D2 (both assert, neither measures) | No | No |
| Function-level detection misses cross-file vulnerabilities | D1, D2, D5 (all assert) | No | No |
| No pairwise error-correlation statistic exists in these five | Verified by inspection of all five | N/A | N/A |

The pattern to notice: the load-bearing claims of this project rest on convergent assertion across reviews rather than on replication. That is weaker than it looks, and the protocol's own evidence classes are what keep it from being overstated.
