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
| [`adversarial-reviewer-corpus-audit.md`](adversarial-reviewer-corpus-audit.md) | Audit of an earlier proposed reading list; separates real sources from plausible-sounding ones |
| [`paper-links-priority.md`](paper-links-priority.md) | The five verified sources with canonical records |

## Sources

| ID | Paper | Record | Peer reviewed |
|---|---|---|---|
| D1 | A Systematic Literature Review on Detecting Software Vulnerabilities with LLMs | [arXiv:2507.22659](https://arxiv.org/abs/2507.22659) | Accepted, TOSEM |
| D2 | LLMs in Software Security: A Survey | [arXiv:2502.07049](https://arxiv.org/abs/2502.07049) | ACM CSUR 58(5) |
| D3 | LLMs Versus Static Code Analysis Tools: A Systematic Benchmark | [arXiv:2508.04448](https://arxiv.org/abs/2508.04448) | No, thesis preprint |
| D4 | Outside the Comfort Zone | [arXiv:2408.16400](https://arxiv.org/abs/2408.16400) | ESORICS 2024 |
| D5 | Vulnerability Detection and Repair: Literature Review | [arXiv:2404.02525](https://arxiv.org/abs/2404.02525) | TOSEM |

## Evidence classification

Every claim in this repository carries a tag:

- `[E]` directly established by the source
- `[A]` author interpretation
- `[I]` independently replicated (none found in this corpus)
- `[D]` derived engineering hypothesis, generated here, unpublished
- `[P]` unverified implementation proposal
- `[C]` contradicted or in tension with another source here

No proposed implementation is presented as a published research finding. Four of the five sources are not open access and are not redistributable; retrieve them from arXiv.

## The three findings that shape the build

1. **Ground truth in this field is not trustworthy.** D4 used Semgrep as an external oracle against five standard benchmarks and found disagreement in both directions. An error-correlation matrix built on unverified labels measures label noise and would be reported as correlated model error.
2. **Localization cannot be taken from the model.** In D3 all three LLMs reported an incorrect line and column for every finding while correctly identifying the file. Findings need content anchors, with lines resolved at display time.
3. **The novelty claim needs narrowing.** D1 documents published agentic review teams and uncertainty-gated human routing. The defensible contribution is mutual refutation requiring a counter-artifact, plus a published pairwise error-correlation matrix and fabrication rate, neither of which appears in these five sources.

## Status

Research-only. No production code. Every item tagged `[D]` or `[P]` is an unreviewed proposal and requires independent engineering review and automated validation before implementation.
