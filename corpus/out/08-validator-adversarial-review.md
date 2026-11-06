# Output 12: Adversarial review of the validators

The remediation PR added seven checks and twenty-five tests, all passing. That proved the checks reject the defects that had already been found. It did not prove they reject the ones nobody has found yet.

This is the follow-up: attack the validators, and record what survives.

The question asked was narrow and correct. Not "are the checks right" but "would a deliberate regression get through them". Those are different questions, and only the second one is about safety.

---

## 1. Method

Twenty mutations, each representing a move an adversary would make to ship a fabricated claim. Three are now blocked by a named check that did not exist when they were written. The remainder are committed as **passing** tests under `test_admits_*`, so the blind spot is asserted in code rather than described as a caveat.

Two of the eighteen blocked cases were only found after the first version of the check failed on the runner and not locally, which is the recurring lesson of this repository: a check that has only ever run on the machine that wrote it has not run.

Treating an admitted hole as a test rather than a note is the point. A caveat in prose rots; a test fails when someone closes the hole, which is the reminder to move it.

```bash
$ pytest -q tests/test_validator_adversarial.py
22 passed
```

---

## 2. Attacks that were not blocked, and the checks added because of them

Six of the sixteen checks now in `tools/validate_corpus.py` exist because a mutation passed the first seven.

| Mutation | Was it caught? | Check added |
|---|---|---|
| Claim `replication_status: "independent"` with no document recording replication | **No** | `replication_claims` |
| Corpus totals inflated to 9 verified documents out of 5 | **No** | `corpus_counts` |
| A non-permissive source added to the redistributable list | **No** | `license_consistency` |
| An `unavailable` locator relabelled `verified` while still `"unresolved"` | **No** | `locator_resolution` |
| `verified: true` added to a document record | **No** | `extension_keys` |
| A table row asserting `Accepted at TOSEM` for D1, added to a README | **No** | `status_language` |

The last one is the finding worth dwelling on. The whole reason PR #3 and PR #4 exist is that a README claimed an acceptance status the provenance report denied. The fix was to correct that sentence. Nothing stopped the next sentence. A prose correction is a one-time repair, and the corpus had already demonstrated it does not hold.

`status_language` now scans every tracked markdown file and requires that an assertive publication phrase carry its basis on the same line.

It has since produced two false positives, both from quoting the thing it hunts. The first flagged the sentence "not a peer-reviewed publication"; the second flagged this document's own table, which quotes `Accepted at TOSEM` inside backticks as an example. Negation and code spans are now handled, and both cases are tests. A checker that cannot read a quotation is a checker people will disable.

---

## 3. Four attacks that still get through

Recorded as `test_admits_*`. Each has a reason and a route to closure.

**Coordinated peer-review downgrade.** Set every document to `unreviewed` and update the roll-up to match, and the validator is satisfied. It checks that the documents and the roll-up agree, not that either is true. *Closure:* an external anchor, meaning a fetch of the publisher or arXiv record at build time. That is a network dependency, so it belongs in a scheduled job rather than an offline validator.

**Wholesale source substitution.** Change the `arxiv_id`, the `source_url` and the `title` together and every check passes. There is no content fingerprint binding the record to the document it claims to be. *Closure:* compare the stored title against the arXiv API, again a network check. The cheap offline half is already done: `arxiv_id` must equal the id embedded in `source_url`, which forces an adversary to change both and makes the substitution visible in a diff.

**A plausible invented locator.** `{"section": "III Methods"}` marked `verified` passes the section-existence check, because verifying a section name requires the source text, and the source text is deliberately not in the tree. *Closure:* partial, as of the `locator_witness` check. A verified claim must now carry a verbatim quote, its offset, its length and a retrieval id that resolves to a recorded artifact hash, so an invented section has to be accompanied by an invented sentence that someone can disprove by re-fetching. That raises the cost of fabricating a locator from typing a section number to producing a witness that survives `curl | sha256sum`. It does not verify the quote's aptness offline; only review does that. The validator can force a claim to be *checkable*. It cannot check it.

**A trivially true claim.** "The paper exists and contains words about the topic" passes every field check. Shape is enforceable; meaning is not. *Closure:* review. Stated plainly because a validator that appears to validate claim quality would be worse than no validator.

---

## 4. Residual risk, ranked

1. **Locator truth.** The largest gap by volume: seven of ten claims have no locator at all, and the three that do were verified against text that is no longer in the tree. Anything citing those three should re-fetch before relying on them.
2. **Source identity.** No fingerprint ties a metadata record to a document.
3. **External status.** Peer-review and retraction status are self-reported by this repository.
4. **Claim meaning.** Not addressed, and not addressable by schema.

Everything in the validator checks **internal consistency**. None of it establishes that an external fact is true. That is a narrower guarantee than "verified", and the documentation now says so in the places where it previously implied more.

---

## 5. Documentation consistency after the merges

The merged main was swept for language contradicting the corrected licensing and evidence positions. Three items were stale:

- `02-engineering-translation.md` still specified a three-way disposition including `auto-clear`, while its own amendment withdrew it. The original line is now marked superseded in place rather than deleted, because the record of what was specified is part of the evidence.
- `README.md` still advertised 24 tests and four checks, both stale by the time of the merge.
- `04-provenance-and-licensing.md` had a table column headed "Peer reviewed" holding values that were bases, not confirmations. Renamed.

One ambiguity was also scoped: `adversarial-reviewer-corpus-audit.md` has a `Verified` column that means the identifier resolves to a real document, not that its results were checked. It now says that above the table.

**None of this is entrusted to future care.** `status_language` fails the build on an unqualified publication claim, and `peer_review_tiers` fails it when a document and the roll-up disagree.

---

## 6. What the validators still cannot do

They cannot tell you a claim is true. They can tell you that a claim marked `security_rule` is verified and located, that its locator is not a placeholder, that the document it belongs to is licensed for the use claimed, that the counts describing the corpus reconcile with its contents, and that no document in the repository asserts a status its own metadata denies.

That is a real guarantee and a narrow one. The gap between it and "this vulnerability is real" is where the harness comes next.
