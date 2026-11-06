# Research corpus run: Adversarial Code Reviewer

Run date 2026-11-06. Five documents acquired, validated and extracted. Full texts retrieved, not abstracts.

## Outputs

| # | Protocol output | File |
|---|---|---|
| 1 | Structured research metadata | `research-metadata.json` |
| 2 | Technical extraction | `01-technical-extraction.md` |
| 3, 4, 5 | Repository relevance map, implementation opportunities, tests and benchmarks | `02-engineering-translation.md` |
| 6, 7 | Contradictory findings and unresolved research questions | `03-contradictions-and-open-questions.md` |
| 8 | Provenance and licensing report | `04-provenance-and-licensing.md` |

## Source tree

Retrieved artifacts are in `../`: `abs_*.html` (abstract pages), `html_*.html` (full text), `txt_*.txt` (extracted plain text), `api.xml` (arXiv API metadata).

**These must not be committed to a public repository.** Four of five documents are under the arXiv non-exclusive distribution license, which permits no redistribution. See `04-provenance-and-licensing.md` section 2 before any commit.

## Evidence classification legend

- `[E]` directly established by the source
- `[A]` author interpretation
- `[I]` independently replicated (none found in this corpus)
- `[D]` derived engineering hypothesis, generated here, not published
- `[P]` unverified implementation proposal
- `[C]` contradicted or in tension with another source in this corpus

## Documents

| ID | Short name | arXiv | Peer reviewed |
|---|---|---|---|
| D1 | SLR, detecting vulnerabilities with LLMs (263 studies) | 2507.22659 | Accepted TOSEM |
| D2 | LLMs in Software Security survey | 2502.07049 | CSUR 58(5) |
| D3 | LLMs versus static analysis benchmark | 2508.04448 | No, thesis preprint |
| D4 | Outside the Comfort Zone | 2408.16400 | ESORICS 2024 |
| D5 | Vulnerability detection and repair review | 2404.02525 | TOSEM |

## The three findings that change the plan

1. **Ground truth in this field is not trustworthy.** D4 used Semgrep as an external oracle against five standard benchmarks and found disagreement in both directions: the oracle found only a small fraction of claimed vulnerabilities, and it found vulnerabilities inside code labelled secure. Any error-correlation matrix built on unverified labels measures label noise and would be reported as correlated model error. Label provenance with multi-oracle adjudication has to come before the metric.

2. **Localization cannot be taken from the model.** In D3 all three LLMs reported incorrect line and column for every finding while correctly identifying the file. Reproduction contracts keyed to line numbers will break on a moving repository. Findings need content anchors, with lines resolved at display time.

3. **The novelty claim needs sharpening.** D1 documents published agentic review teams with lister and reviewer agents, and published uncertainty-based routing to human analysts. "Reviewers that investigate each other" is partially pre-empted. The defensible contribution is narrower and stronger: mutual refutation requiring a counter-artifact rather than an opinion, plus a published pairwise error-correlation matrix and fabrication rate, neither of which appears in any of these five documents.

## Constraint that governs the rest

No production code was modified. Every item in `02-engineering-translation.md` tagged `[D]` or `[P]` is an unreviewed proposal and requires independent engineering review and automated validation before implementation, per the protocol.
