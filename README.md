# Adversarial Code Reviewer: research corpus

Evidence base for a multi-model code reviewer in which reviewers must refute each other's findings with reproducible artifacts rather than vote on them.

This repository contains **analysis, metadata and citations only**. It does not contain copies of the source papers. See [LICENSE-NOTICE.md](LICENSE-NOTICE.md).

## What is here

| Path | Contents |
|---|---|
| [`corpus/out/research-metadata.json`](corpus/out/research-metadata.json) | Structured metadata for five sources: provenance, versions, licenses, datasets, results, statistical limits |
| [`corpus/out/01-technical-extraction.md`](corpus/out/01-technical-extraction.md) | Per-document extraction, evidence-tagged |
| [`corpus/out/02-engineering-translation.md`](corpus/out/02-engineering-translation.md) | Repository relevance map, implementation specifications, acceptance criteria, tests |
| [`corpus/out/03-contradictions-and-open-questions.md`](corpus/out/03-contradictions-and-open-questions.md) | Where the sources disagree, and what remains unresolved |
| [`corpus/out/04-provenance-and-licensing.md`](corpus/out/04-provenance-and-licensing.md) | Redistribution constraints and the evidence-status ledger |
| [`corpus/out/05-absurdity-lane.md`](corpus/out/05-absurdity-lane.md) | Hypothesis-generation lane built on absurd-humor properties: operators, output contract, gates, metrics |
| [`corpus/out/06-external-review-response.md`](corpus/out/06-external-review-response.md) | Response to external review: citation verification, triage, seven accepted specification deltas |
| [`corpus/out/07-remediation-log.md`](corpus/out/07-remediation-log.md) | Response to a second review: ten findings triaged, schema and validators added, spec amended |
| [`corpus/out/08-validator-adversarial-review.md`](corpus/out/08-validator-adversarial-review.md) | Attack on the validators: six checks added, four blind spots admitted as tests |
| [`corpus/out/09-oracle-and-pilot-defects.md`](corpus/out/09-oracle-and-pilot-defects.md) | What counts as an oracle, and the pilot the plan was missing |
| [`corpus/out/10-harness-metric-defects.md`](corpus/out/10-harness-metric-defects.md) | Three metric defects: a pilot too small to stratify, unrequired verdicts, a circular fabrication rate |
| [`CHANGELOG.md`](CHANGELOG.md) | Every defect with its reproduction, regression test and method justification |
| [`corpus/out/claims.json`](corpus/out/claims.json) | Claim-level manifest with locators, evidence class and permitted downstream uses |
| [`adversarial-reviewer-corpus-audit.md`](adversarial-reviewer-corpus-audit.md) | Audit of an earlier proposed reading list; separates real sources from plausible-sounding ones |
| [`paper-links-priority.md`](paper-links-priority.md) | The five verified sources with canonical records |

## Sources

| ID | Paper | Record | Peer reviewed |
|---|---|---|---|
| D1 | A Systematic Literature Review on Detecting Software Vulnerabilities with LLMs | [arXiv:2507.22659](https://arxiv.org/abs/2507.22659) | Manuscript-asserted (TOSEM) |
| D2 | LLMs in Software Security: A Survey | [arXiv:2502.07049](https://arxiv.org/abs/2502.07049) | Secondary source (CSUR) |
| D3 | LLMs Versus Static Code Analysis Tools: A Systematic Benchmark | [arXiv:2508.04448](https://arxiv.org/abs/2508.04448) | Unreviewed preprint |
| D4 | Outside the Comfort Zone | [arXiv:2408.16400](https://arxiv.org/abs/2408.16400) | Manuscript-asserted (ESORICS 2024) |
| D5 | Vulnerability Detection and Repair: Literature Review | [arXiv:2404.02525](https://arxiv.org/abs/2404.02525) | Secondary source (TOSEM) |

## Checks

Metadata is enforced, not just documented. On every push and pull request:


```
python tools/validate_corpus.py   # 16 checks: schema, provenance, evidence gates, licensing, counts, docs
pytest -q                         # 88 tests: negative cases, adversarial attacks, admitted blind spots
python tools/repro.py --check     # 23 defects: each reproduces on its historical state, then stays caught
```

Sixteen checks, not four. The later ones were added by attacking the validators themselves: six of them exist because a mutation got through the first version. The four mutations that still get through are written as passing tests, so the limits are visible in code rather than discovered in an incident. See [`corpus/out/08-validator-adversarial-review.md`](corpus/out/08-validator-adversarial-review.md).

Both pass locally and on the runner (Python 3.11, `ubuntu-latest`).

The gate that matters most: a claim may only be used as a `security_rule` if it is both verified against the source and carries a verified locator, and never if it is an interpretation or a derived inference. Ten claims are currently in the manifest; three are verified against retrieved text, seven have no locator that can be produced from material in the tree and are marked unavailable rather than guessed.

## Where this repository broke its own rules

The rule is stated in the standing instructions and repeated throughout: nothing lands without independent review, and no change reaches a protected branch on trust. It has been broken once, and the record belongs here rather than in a commit message nobody reads.

**2026-11-06: direct push to `main`.** Two commits landed on `main` without a pull request. They were the validator hardening commit `c8300b55` and the fix that followed it. The content was tested, every check green and the suite passing, and that is exactly why this is worth recording: the work was fine and the process was not. A change that proves itself after the fact has still skipped the step that exists to catch the change that does not.

The commit was made by an AI agent working on the maintainer's behalf, against a checked-out `main`. The maintainer is accountable for it, because authorising an agent to work in a repository is authorising its mistakes along with its work. The agent disclosed it in the same message that reported the result, which is the only part of this that went right.

**What changed as a result.** Branch protection is now enabled on `main`: pull requests are required, the required status check must pass, force-pushes and branch deletion are blocked.

**That check is named `corpus`, not `validate`, and the difference is a trap.** `validate` is the workflow name in `.github/workflows/validate.yml`. `corpus` is the single job inside it. GitHub registers required status-check contexts by job name, so protection is configured against `corpus` while everything a reviewer sees in the Actions tab is labelled `validate`. Set the requirement to the workflow name and it matches no context, so it is never satisfied: merges stay blocked with a green tick on the pull request.

The error message does not help. This repository's first blocked merge failed with `Required status check "corpus" is expected` while `corpus` had already passed twice on that commit. The actual cause was `strict: true` with the branch behind base, so the checks GitHub was waiting for belonged to a merge commit that did not exist yet. A message naming the check sent the investigation to the check. Recorded because the next person will read the same message.

**The first attempt at that fix did not hold, and the failure is instructive.** Protection was enabled with `enforce_admins` off, and the next direct push succeeded anyway. GitHub said so plainly:

```
remote: Bypassed rule violations for refs/heads/main:
remote: - Required status check "corpus" is expected.
```

A rule the repository owner can bypass is not a rule, it is a preference. `enforce_admins` is now on, and a direct push is rejected with `protected branch hook declined`. That test push left a throwaway commit on `main`, which is reverted rather than force-deleted, because force-push is now blocked for exactly the reason it should be.

This is the same failure mode as the license paragraph and the fabricated citations, at the level of process instead of prose: something that looked like enforcement while being advisory. The pattern has now occurred five times in this project. It is the actual subject of the repository.

The rule is enforced by the platform instead of by intention: a standard that lives in prose is a standard that has already been broken once.

## Declared controls and effective controls

This repository started as a joke about whether absurdity could sharpen an adversarial code review. That is not a summary of the joke, which was vulgar and is not reproduced here. It is an accurate description of what survived: a reviewer primed to violate expectations may notice what a disciplined one walks past, which turned into a corpus, which turned into a review, which turned into this.

The joke did not produce a theory of software quality. It produced a worked demonstration of one failure mode, five times over, close enough together that the shape became hard to ignore.

**The shape.** A policy exists. A configuration claims to enforce it. The execution path permits an exception. Someone tests the boundary and finds the gap.

| # | Declared control | What actually happened |
|---|---|---|
| 1 | CC BY-SA requires the whole compilation to carry the license | ShareAlike attaches to adapted material, not to a collection holding an unmodified work. The claim was wrong and is withdrawn. |
| 2 | Sources listed as verified | Several named papers did not exist. Verification meant the identifier resolved, and for those it did not. |
| 3 | `schema_version: "1.1"` | Nothing validated against it for the first three revisions. A version number with no validator is a comment. |
| 4 | The CI gate | The workflow file sat outside `.github/`, and the dev requirements were excluded by a `*.txt` ignore rule. The first armed run failed before executing a single check. |
| 5 | Branch protection requiring the `corpus` status check | Enabled with `enforce_admins` off. The next direct push succeeded, tagged `Bypassed rule violations`. |

Entries 4 and 5 share a cause worth naming: both controls were reported as working before anything had exercised them. The workflow was described as the gate while it was a file in the wrong directory; the protection was described as binding while the account making the pushes could step around it. Neither was a lie. Both were configuration mistaken for behavior.

**The difference that mattered.** Entry 5 was found by pushing to main and reading the rejection, not by reading the settings. A configuration is a claim about what should happen. A rejected push is evidence about what does. The repository now prefers the second, which is the same rule it applies to vulnerability claims, arrived at by failing to apply it to itself.

**Why the agent's own failure is in here.** The README records that an AI agent working in this repository pushed directly to main, that the content passed its tests, and that the process violation counted anyway. Automated contribution is not evidence of correctness. A contributor whose errors go unrecorded is a control that has never been tested, and the intent here is to test it in public.

The soundtrack to this was apparently Steel Panther's *Community Property*. That is not a methodology endorsement, and no part of the corpus validates it.

## Evidence classification

Every claim in this repository carries a tag:

- `[E]` directly established by the source
- `[A]` author interpretation
- `[I]` independently replicated (none found in this corpus)
- `[D]` derived engineering hypothesis, generated here, unpublished
- `[P]` unverified implementation proposal
- `[C]` contradicted or in tension with another source here

Peer-review status is tiered: **publisher-confirmed**, **manuscript-asserted**, **secondary source**, **unreviewed**. No publisher record was opened for any source in this pass, so nothing here is publisher-confirmed. See [corpus/out/04-provenance-and-licensing.md](corpus/out/04-provenance-and-licensing.md).

No proposed implementation is presented as a published research finding. Four of the five sources are not open access and are not redistributable; retrieve them from arXiv.

## The three findings that shape the build

1. **Ground truth in this field is not trustworthy.** D4 used Semgrep as an external oracle against five standard benchmarks and found disagreement in both directions. An error-correlation matrix built on unverified labels measures label noise and would be reported as correlated model error.
2. **Localization cannot be taken from the model.** In D3 all three LLMs reported an incorrect line and column for every finding while correctly identifying the file. Findings need content anchors, with lines resolved at display time.
3. **The novelty claim needs narrowing.** D1 documents published agentic review teams and uncertainty-gated human routing. The defensible contribution is mutual refutation requiring a counter-artifact, plus a published pairwise error-correlation matrix and fabrication rate, neither of which appears in these five sources.

## Status

Research-only. No production code. Every item tagged `[D]` or `[P]` is an unreviewed proposal and requires independent engineering review and automated validation before implementation.
