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
python tools/validate_corpus.py   # 13 checks: schema, provenance, evidence gates, licensing, counts, docs
pytest -q                         # 47 tests: negative cases, adversarial attacks, admitted blind spots
```

Thirteen checks, not four. The later ones were added by attacking the validators themselves: six of them exist because a mutation got through the first version. The four mutations that still get through are written as passing tests, so the limits are visible in code rather than discovered in an incident. See [`corpus/out/08-validator-adversarial-review.md`](corpus/out/08-validator-adversarial-review.md).

Both pass locally and on the runner (Python 3.11, `ubuntu-latest`).

The gate that matters most: a claim may only be used as a `security_rule` if it is both verified against the source and carries a verified locator, and never if it is an interpretation or a derived inference. Ten claims are currently in the manifest; three are verified against retrieved text, seven have no locator that can be produced from material in the tree and are marked unavailable rather than guessed.

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
