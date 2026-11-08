# Acquisition batch 2: two admitted, two refused

**Received:** 2026-11-08, four links, no stated purpose.
**Outcome:** two documents admitted (D6, D7), two refused with reasons (RS1, RS2). The corpus now holds seven documents, of which zero are publisher-confirmed.

This batch is different in kind from the first five. Those were chosen because they bear on LLM code review. These are malware-taxonomy sources offered without a stated question, and honesty requires saying up front what they can and cannot support: **none of them informs the project's central claim**, which is about pairwise reviewer error correlation. Two are admitted on narrower grounds, recorded per document in `relevance_to_project`.

## What was retrieved

| Source | Identity verified how | Retrieval | Decision |
|---|---|---|---|
| Malpedia families index | Fraunhofer FKIE CAAD; page title "Malware Families"; 207 family and actor entries linked | `D6-2026-11-08-index`, hash recorded | Admitted, `unreviewed` |
| arXiv:2403.02546 | Google Scholar redirect resolved to arXiv; authors, date and ISDFS acceptance confirmed via the arXiv API; PDF retrieved | `D7-2026-11-08-pdf`, hash recorded | Admitted, `manuscript_asserted` |
| EvilMutex malware index | HTTP 200, 73 KB Nuxt single-page app, 207 family links, no author, no about page, no license | retrieved, then refused | Refused, `provenance_unestablished` |
| Medium article | HTTP 403 Cloudflare interstitial; second route also 403 | never retrieved | Refused, `unretrievable` |

The Google Scholar link is a redirect wrapper, not a source. It was resolved to `arxiv.org/abs/2403.02546` before anything was recorded, because a redirect URL cannot be re-fetched by a reader following the metadata.

## D7: what it is actually good for

Eren et al. report family classification that holds up under class imbalance, and they are explicit that the stability is bought with abstention. Three claims were extracted, each with a verbatim quote and character offset into the retrieved PDF, so a reader can re-fetch the artifact, confirm the hash, and land on the sentence.

The relevance is narrow and real. S7 asks for per-class reporting because pooled accuracy hides exactly this failure; S8 asks for abstention that tracks actual uncertainty. This paper is evidence that the trade-off is measurable in an adjacent domain, and its risk-coverage framing is a better template than a single F1. It is **not** evidence that abstention calibration transfers to code review, and the claims are marked `design_input` and `hypothesis_seed` for that reason, never `security_rule`.

Acceptance at ISDFS 2024 is asserted in the arXiv comment field only. No publisher record was opened, so the tier is `manuscript_asserted`, not `publisher_confirmed`. The arXiv admin note also records text overlap with arXiv:2309.01350; that is disclosed in the metadata rather than smoothed over, because a corpus about provenance cannot quietly omit an overlap notice.

## D6: a database, admitted without claims

Malpedia supplies naming: family and actor identifiers that a later abuse-potential reviewer would need to speak about malware at all. It was admitted as `unreviewed`, which for a curated database means "no editorial or peer-review process is stated", not "low quality". Fraunhofer FKIE is the operator and the entries cite external reporting.

No claims were drawn from it, deliberately. An index is not evidence; its value is that its entries point at primary reporting, and those pointers are where claims would come from. Admitting it with zero claims keeps it out of the evidence path while making the naming scheme available.

No license was found. `faq`, `about`, `terms`, `legal` and `imprint` all return 404, and the families page carries no terms link. The license field says exactly that, and the source is treated as non-redistributable. Absence of a license is not permission.

## The two refusals

**EvilMutex (RS1).** Retrieved successfully, which makes it more tempting than an unreachable source, and that is the trap. There is no named author, no methodology, no license and no citation of sources anywhere in the index. Content whose authorship cannot be established cannot be attributed, and unattributed security claims are the failure this project exists to measure. Refused for provenance, not for quality, since quality was never assessable.

**Medium (RS2).** Two retrieval routes returned 403: a direct request with a browser user agent, and a reader proxy, which reported that anonymous access to `medium.com` was itself blocked after abuse from an unrelated page. The article was never seen. Nothing is recorded about its contents, its accuracy or its author, because a description of a page nobody read would be invented, and this corpus has already had one round of invented citations.

Both refusals live in `research-metadata.json` under `rejected_sources`, with the attempts that justify them, and `check_rejected_sources` now fails the build if a refusal appears with no attempt, an unknown reason, or evidence too thin to check. A refusal is a claim too.

## What this batch does not do

- It adds no evidence about reviewer error correlation, fabrication rates, or code review at all.
- It does not raise the count of publisher-confirmed sources: that number is still zero, and the README says so.
- It does not make the corpus "seven sources on code review". It is five on code review, one taxonomy database, and one paper from an adjacent field, and the relevance field on each document is the honest place that distinction lives.
