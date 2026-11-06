# Output 11: Remediation log

Response to a second external review, this one a conventional repository review covering correctness, consistency, data integrity, licensing and maintainability.

The review's summary judgement was that the repository's documentation promises stronger evidence discipline than its tooling enforces. That is accurate, and it is the defect this commit addresses. Documentation now has machinery behind it.

---

## 1. Triage

| # | Finding | Severity claimed | Decision |
|---|---|---|---|
| 1 | D3 score attribution inconsistent | P1 | **Accepted, resolved better than asked** |
| 2 | Peer-review status inconsistent | P1 | **Already fixed in the stacked commit; extended here** |
| 3 | ShareAlike propagation overstated | P1 | **Accepted. Legal claim was wrong** |
| 4 | No machine-enforceable schema | P1 | **Accepted. Built** |
| 5 | Reproducibility depends on unpublished files | P2 | **Accepted. Claim manifest added** |
| 6 | Contamination test has a confound | P2 | **Accepted. Design amended** |
| 7 | Reproduction gate too restrictive | P2 | **Accepted. Evidence contracts by category** |
| 8 | Dependency freshness conflated with vulnerability | P2 | **Accepted. Four states separated** |
| 9 | Error correlation needs statistical safeguards | P2 | **Accepted. Undefined cells and strata required** |
| 10 | Automatic clearance premature | P1 | **Accepted. Auto-clear withdrawn** |

---

## 2. The two that mattered

### Finding 3 was a correct catch on a wrong legal claim

The previous text said a compilation incorporating CC BY-SA material must itself be licensed CC BY-SA. That is not what the license says. ShareAlike attaches to **Adapted Material**, not to a collection that merely includes an unmodified work. Creative Commons states that a compilation need not be released under a ShareAlike license, while each included work stays under its own terms and any modified version acquires the license.

The practical policy survives unchanged, because separation is still the right way to handle mixed redistribution rights, but its stated reason was wrong and has been replaced. The paragraph now separates original material, adaptations, and this repository's own notes, and it says plainly that it is a reading of the license and the licensor's FAQ rather than legal advice.

This is the second time in this project that a confident, plausible-sounding structure turned out not to hold: first fabricated citations in a proposed reading list, now an overbroad license claim in my own report. The pattern is worth naming. Prose that reads like a conclusion is the easiest thing to accept without checking.

### Finding 1 was true, and verifiable

The metadata carried a caveat that the tool-to-score mapping was inferred from the order tools appeared in the abstract, while three documents presented per-tool F1 scores as established results. That is a provenance failure regardless of whether the numbers are right.

Rather than downgrade the claim to `provisional`, the retrieved full text was checked. The paper states the mapping explicitly in Section V:

> The static analysis tools SonarQube, CodeQL, and SnykCode achieved average F1 scores of 0.260, 0.386, and 0.546, respectively.

So the inference was correct and the caveat can be replaced by a locator. `mapping_status` is now `verified_against_source` with `{section: "V Analysis of Results", table: "Table XIII"}`, and claim D3-C01 carries the same record.

**Worth stating:** the result was right and the process was still wrong. An inferred mapping that happens to be correct is indistinguishable, from the outside, from an inferred mapping that is not.

---

## 3. What was built

```
schemas/
    research-metadata.schema.json    JSON Schema 2020-12, enums for every status field
    claim.schema.json                claim records with locators and permitted uses
tools/
    validate_corpus.py               schema + referential integrity + evidence gate + licensing guard
tests/
    test_metadata_schema.py          schema rejects malformed documents
    test_citations.py                identifiers, URLs and tier roll-ups agree
    test_claim_manifest.py           the downstream-use gate holds
.github/workflows/validate.yml       runs both on every push and pull request
corpus/out/claims.json               ten claims, locator-typed
```

**Enforcement, not documentation.** The specific checks, each tied to an observed defect:

| Check | Defect it prevents |
|---|---|
| `code_available` and friends are enums | A field that is `true` in one record and `"partially"` in another |
| DOI must match `10.x/y` or be null | Sentinel strings like `not_resolved` posing as identifiers |
| `arxiv_id` must equal the id inside `source_url` | Citation rot between the record and the link |
| Document tier must equal the corpus-level roll-up | A README claiming acceptance the provenance report denies |
| `security_rule` requires verified claim and verified locator | Promoting an unverified or interpretive claim into a rule |
| Interpretation and inference barred from `security_rule` | An author's opinion becoming a detector |
| No `.pdf`/`.txt`/`.html` bodies tracked | Redistributing four sources that permit no redistribution |
| No tracked file over 512 KB | An accidental full-text commit |

Ten of ten source claims in the manifest report `replication_status: none`, and a test enforces that this cannot quietly change.

---

## 4. Specification amendments

**S2, contamination.** The probe compared public repositories against mutations that move a vulnerability across a function boundary. The reviewer is right that this confounds contamination with mutation difficulty. A vulnerability can be harder to find because it is harder to analyse. The design now requires an unchanged-code control, a semantics-preserving transformation that does not move anything, an equivalence check on each mutant, and a separate difficulty measurement. The 15-point threshold is marked as uncalibrated rather than presented as a decision rule.

**S4, verification gate.** The old rule required a reproduction artifact for every shipped finding. That is right for exploitable vulnerabilities and wrong for architecture, logic, reliability and maintainability findings, which the system is also meant to produce. Evidence contracts are now defined per category. Two guards stop the loosening from becoming a fabrication channel: each contract must be as hard to fabricate as a reproducer, and `unverified_suspicion` stays a separate stream that no metric counts as a finding.

**S5, dependencies.** Four states, four evidence sources: `outdated`, `known_vulnerable`, `unsupported`, `unknown`. Version age is not evidence of vulnerability.

**S6, correlation.** Phi is undefined when a reviewer makes no errors. That cell is reported as undefined, with joint counts, bootstrap intervals, raw overlap and per-class strata. The 0.8 figure is an inspection trigger, not a definition.

**S8, routing.** Auto-clear is withdrawn. The circularity the reviewer identified is total: an uncalibrated uncertainty measure deciding whether a human must check what that measure concluded. Two dispositions remain, `human_review` and `quarantine`, until a published calibration study on held-out code shows the threshold holds.

---

## 5. What was not done

**No claim locators were invented.** Ten claims are in the manifest. Three are marked `verified` because they were re-checked against retrieved text in this pass. The other seven carried `section: "unresolved"`. A later pass renamed that state to `unavailable`, because a locator that cannot be produced is not a locator that is merely unchecked, and calling it provisional flattered it. That includes D4-C01, the Semgrep-oracle claim that the entire label-provenance architecture rests on. Marking it provisional is uncomfortable and correct: the full texts from the acquisition run are not in the tree, so its locator cannot be re-established without re-retrieval.

**CI took three attempts, and the middle one is the instructive one.** GitHub refuses any push creating `.github/workflows/*.yml` without the `workflow` OAuth scope, so the workflow first landed at `ci/validate.yml`; the scope was then granted and the file moved. The first armed run failed at dependency installation: `requirements-dev.txt` was never committed, because `.gitignore` carried a blanket `*.txt` rule written to keep retrieved full texts out of the tree, and it swallowed the requirements file with them.

That failure was only possible because the check ran somewhere other than my machine. It also exposed a second-order bug: the licensing guard itself flagged `.txt` files anywhere in the repository, so committing the requirements file would have tripped the very check meant to protect redistribution. Both are fixed. The guard now scopes `.txt` and `.html` to the corpus tree and still blocks `.pdf`, `.epub` and `.docx` anywhere, with a test covering both directions.

**No CI result is claimed here that was not observed.** Run [42299428790](https://github.com/1243353366/adversarial-code-reviewer-corpus/actions/runs/42299428790) on `ubuntu-latest`, Python 3.11, all six steps executed: validator 7/7 PASS, **25 passed**. An earlier run on the same branch failed at dependency installation, and that failure is recorded above rather than deleted.

**No implementation of the reviewer itself.** The review recommends fixing controls before adding papers. Same logic applies to code: the harness comes before the detector, and the schema comes before both.

---

## 6. Verification

Run in this pass, on this tree:

```
$ python tools/validate_corpus.py
[    PASS] metadata_schema
[    PASS] claim_schema
[    PASS] doc_ids
[    PASS] arxiv_urls
[    PASS] peer_review_tiers
[    PASS] claim_gate
[    PASS] licensing_guard

$ pytest -q
25 passed
```

On the runner, same tree, same commit: 7/7 PASS and 25 passed.

The validator failed on first run, on `doi: 'not_resolved'` in three records and a month-precision version date. Those were real defects of the kind the review predicted, found by the tooling on its first execution, which is the argument for the tooling.

The count in this log has now been wrong once, in the direction of optimism: 24 tests were claimed while the runner could not install its dependencies, and one of the 24 was added before the file that installs them was committed. Everything above is stated from the run log, not from intent.
