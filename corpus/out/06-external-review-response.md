# Output 10: External review response and specification deltas

An external reviewer inspected the repository and returned five findings, two documentation corrections, a research-exercise proposal, and four citations offered as support for the humor-to-review translation.

This document treats that review as **useful but untrusted input**. Every item is triaged: accepted, accepted with modification, or rejected, with a reason. Citation claims were verified independently before anything built on them.

Status of the accepted deltas: `[D]` design, unreviewed, not implemented.

---

## 1. Citation verification

All four references exist and are correctly described at the bibliographic level. Verified against Crossref records, not against the reviewer's summary.

| Reference | Verified record | Status |
|---|---|---|
| Hull, Tosun and Vaid (2017) | "What's so funny? Modelling incongruity in humour production", *Cognition and Emotion* 31, 484-499. DOI 10.1080/02699931.2015.1129314 | Real. Claim about its findings not verified beyond title |
| Dong, Han, Yang and Chen (2025) | "Humor Production Promotes Creativity: The Mediating Role of Self-Efficacy and the Moderating Role of Fear of Authority", *Behavioral Sciences* 15(8), 1003. DOI 10.3390/bs15081003 | Real. Abstract read |
| Chi, Yin, Cai and Li (2026) | "Sparking Innovation Through Humor: A Meta-Analysis of Leader Humor, Creativity Versus Innovative Behavior, and Contextual Contingencies", *Journal of Leadership & Organizational Studies*. DOI 10.1177/15480518261439446 | Real. Abstract not retrieved |
| Biemans and Huizingh (2024) | "Why so serious? The effects of humour on creativity and innovation", *Creativity and Innovation Management*. DOI 10.1111/caim.12587 | Real. Abstract not retrieved |

**What the strongest one actually shows.** Dong et al. ran four studies (N = 175, 243, 225, 433) using a cartoon humor production paradigm. Humor production correlated with creativity; self-efficacy mediated; fear of authority moderated. Creativity is measured with psychological instruments, in students and workplace samples.

**The transfer gap is total.** None of the four examines software, code review, security, engineering output, or adversarial analysis of any kind. Three are organizational-behaviour studies about leadership and workplace creativity. The meta-analysis is in a management journal. The distance from "producing cartoons correlates with divergent-thinking scores" to "an irreverent reviewer finds vulnerabilities that a sober reviewer misses" is the entire research question, not a premise for it.

So the review's own hedge is the correct reading: these support investigating the idea, and establish nothing about performance. `[E for the bibliographic facts] [D for the transfer, which remains untested]`

The reviewer reached this conclusion independently and stated it plainly. Credit where due: the citations are real, which is more than the earlier proposed reading list managed.

---

## 2. Triage of findings

| # | Finding | Decision |
|---|---|---|
| 1 | Evidence provenance is a convention, not an enforcement mechanism | **Accepted.** Correct and specific |
| 2 | Reviewer independence is overstated unless measured | **Accepted, extended.** Control matrix is better than my S6 |
| 3 | Refutation can become another hallucination channel | **Accepted.** Exposes a real hole in S4 |
| 4 | Prompt injection needs a first-class threat model | **Accepted.** Promotes an `[P]` concern to a requirement |
| 5 | Benchmark needs more than accuracy; add time-to-verified-finding | **Accepted.** The cost argument is the sharpest part |
| A | Peer-review status conflates asserted with confirmed | **Accepted.** My defect. Fixed in this branch |
| B | Preserve the zero-replications distinction downstream | **Accepted.** Already stated; now enforced in the schema |

---

## 3. Deltas

### Delta 1. Claim schema with enforcement (from Finding 1)

The reviewer's point is exact: `[E]` / `[A]` / `[D]` / `[P]` are prose tags. Nothing stops a pipeline from promoting an author's interpretation to a rule.

**Claim record, mandatory fields.** `claim_id`, `source_id`, `locator` (page, section, line range), `evidence_class`, `verification_status`, `replication_status`, `contradicting_evidence[]`, `permitted_downstream_uses[]`.

**The enforcement, not just the fields.** `permitted_downstream_uses` is a closed enum: `citation_only`, `hypothesis_seed`, `design_input`, `security_rule`. A gate rejects any artifact that cites a `citation_only` claim inside a security rule, and any rule whose supporting claims lack `verification_status: verified`. Prose tagging cannot do this because it is not machine-readable; the schema can.

**Where it lives.** In the Corpora layer, upstream of every consumer. If enforcement lives inside a consumer, each consumer enforces differently and the corpus stops being a single source of truth.

### Delta 2. Independence control matrix (from Finding 2)

My S6 measured pairwise error correlation across reviewers. That answers whether the ensemble is diverse. It does not answer *why*, and the reviewer's distinction is the right axis: **diversity of reasoning versus diversity of evidence.**

Six cells, all reported:

| Control | Varies | Isolates |
|---|---|---|
| Same model, different prompt | reasoning only | prompt-induced diversity, the cheapest fake diversity |
| Same model, different oracle | evidence only | whether disagreement tracks what each reviewer can check |
| Different model, same prompt | weights only | model-induced diversity with evidence held constant |
| Different model, different oracle | both | the shipped configuration |
| Same configuration, repeated runs | sampling noise | run-to-run variance, needed before any difference is called real |
| Same reviewer, duplicated | nothing | control; correlation must approach 1.0 or the metric is broken |

Report every cell with a bootstrap interval. A pair that scores well on the shipped configuration but not on the evidence-only cell is producing *reasoning* diversity, which is the kind that evaporates on novel vulnerability classes.

**Dependency.** The evidence-only cell requires each reviewer to be bound to a distinct executable oracle, which is already the project's position and is not optional for this measurement.

### Delta 3. Refutation execution layer (from Finding 3)

This is a genuine hole. S4 said a finding ships only with a reproducer, and that a challenger may submit a counter-artifact. It did not say who executes them.

**A fabricated counter-artifact is still fabricated**, and my design let the challenger's claim enter adjudication as text.

Revised flow:

1. Reviewer submits a finding with a reproducer.
2. Challenger submits a counter-artifact: a demonstration that the finding does not reproduce, or that the claimed guard exists.
3. **An independent executor** runs both against a clean checkout and records raw output.
4. The adjudicator receives **execution evidence only**: exit codes, diffs, captured output. Not either party's explanation.
5. Neither party may execute its own artifact for the record, and neither may grade the other's.
6. Unresolved stays unresolved. There is no tie-break by plausibility.

**Consequence for metrics.** Refutation fabrication becomes its own measurable quantity: counter-artifacts whose claims do not survive independent execution. The reviewer is right that this is distinct from detection fabrication, and failing to separate them hides which component is failing.

### Delta 4. Prompt injection as a requirement (from Finding 4)

Previously an `[P]` engineering concern in `02-engineering-translation.md`. Now a first-class invariant.

**Invariant.** All model-visible repository material is untrusted data. Escaping is necessary and insufficient; the requirement is that no instruction found inside reviewed content can alter control flow, tool selection, adjudication, or output schema.

**Attack surface to test, minimum:** code comments; README and docs; test fixtures and golden files; commit messages and branch names; dependency metadata and lockfiles; generated documentation; Unicode bidi and homoglyph tricks; and instructions aimed specifically at the adjudicator rather than the reviewer.

**Acceptance.** A repository containing an explicit instruction to downrank a real finding must produce the same result as the same repository with that instruction removed.

### Delta 5. Metric extension (from Finding 5)

Added to the existing set:

- **Localization accuracy** against the content anchor (S1), not against line numbers, since D3 shows line reporting is unreliable `[E]`.
- **Refutation success** and **refutation fabrication**, reported as a pair, never one alone.
- **Abstention calibration**: does stated uncertainty track actual error rate? Measured with a reliability curve, not a single score.
- **Cross-file detection**, reported separately from single-file detection, since the literature predicts these diverge (D1, D2, D5 `[E]`).
- **Time to verified finding**, and its inverse, analyst minutes per confirmed finding.

**The cost argument is the strongest sentence in the review.** A reviewer that surfaces 100 suspicions and costs an engineer three hours of elimination can be worse than one that surfaces eight and costs twenty minutes. This should be a headline metric, not a footnote, because it is the one that decides whether anyone uses the system.

### Delta 6. Ablation with a pre-registered kill criterion (from section 6)

Run the benchmark with and without the absurdity lane. Report incremental verified findings, incremental false positives, review time, and newly covered vulnerability classes.

**Kill criterion:** if incremental verified findings is not distinguishable from zero, the lane is removed. Fixed before the first run.

**One correction.** The reviewer's "if it doesn't improve performance, remove it" needs a power caveat. D3's benchmark has 63 vulnerabilities; a null result on a suite that size is uninformative, not a refutation. The ablation needs either a larger suite or an explicit statement that the test is underpowered, and that statement must be published with the result rather than discovered afterwards.

### Delta 7. Category violation as a sixth operator (from section 3, mode 4)

This is the one substantive addition to my five operators, and it is a good one.

**O6. Category violation.** Look for a value being treated as something it is not. The reviewer's examples are precise: a string treated as a trusted identifier, a timestamp treated as proof of freshness, a successful HTTP response treated as proof of authorization.

This is not the same as invariant inversion (O2). O2 negates a precondition. O6 keeps the precondition and attacks the *type* of the thing satisfying it, which is how confused-deputy and object-reference bugs arise. Add it.

Their mode 1 (incongruity) and mode 2 (expectation inversion) and mode 5 (associative recombination) and mode 6 (irreverence) map onto O1, O2, O4 and O5 respectively. Their mode 3 (contextual absurdity) is O3 with a worked example, and the nightclub-bouncer case is a better illustration of identity-versus-ticket checking than anything in my draft.

---

## 4. What I am rejecting or modifying

**Rejected: the proposed module tree.**

```
absurdity_adversarial_engine/
    evidence_validator.py
    calibration.py
```

Placing the evidence validator inside the generator module violates the architecture the review itself argues for. A component that cannot be trusted to validate its own rebuttal cannot host the code that validates evidence. `evidence_validator` and `calibration` belong in the harness, with no import path from the generator. This is not a style point; it is the one-way constraint in `05-absurdity-lane.md` section 1, and the tree breaks it.

**Deferred: writing the module now.**

Not because it is wrong, but because it cannot be evaluated. The lane's value is defined as incremental verified findings, and there is no harness, no ground truth with label provenance (S3), and no oracle binding (S6) in place. A module written today would produce hypotheses nothing can score. The order is harness, then lane, then ablation.

**Modified: "a better research question than whether funny people write better code."**

Agreed, and stated more sharply: the question is whether incongruity-driven generation adds recall **per unit of analyst time** without inflating premise error. The second clause is what makes it falsifiable, and it is the clause the funny-people framing drops.

---

## 5. Documentation corrections applied in this branch

**A. Peer-review status is now tiered.** The previous corpus-level list grouped an asserted acceptance with confirmed publications, which the reviewer correctly flagged.

- `publisher_confirmed`: none. No publisher record was opened for any source in this pass.
- `manuscript_asserted`: D1 (TOSEM), D4 (ESORICS 2024).
- `secondary_source`: D2 (CSUR), D5 (TOSEM), both supported only by citing works.
- `unreviewed`: D3.

**B. Replication status is now a required field.** The zero-of-five figure is not a note in a report; it is a field each claim carries, and a downstream rule may not cite a claim whose `replication_status` is `none` as if it were independently established.

---

## 6. Net effect on the project

The review's strongest contribution is not the humor taxonomy, which was already in hand, and not the citations, which support a weaker claim than they appear to. It is Finding 3: **the refutation channel was itself unvalidated.** My design treated a counter-artifact as evidence because it was an artifact, which is exactly the error this project exists to catch, committed one level up.

Second strongest: the analyst-time metric. An adversarial system that manufactures work is a net negative however many findings it produces.

Verdict on the review itself: accurate on the repository's actual defects, correct that independence must be measured rather than asserted, and honest about the limits of its own citations. Its one design error is placing the validator inside the generator, and that is the error the whole architecture is built to prevent.
