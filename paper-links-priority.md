# Paper link priority: verified records

All five located against arXiv primary records on 2026-11-06. Priority labels as supplied, with a note on what each one actually gives the Adversarial Code Reviewer.

---

## Critical

### 1. A Systematic Literature Review on Detecting Software Vulnerabilities with Large Language Models (2025)

- arXiv: https://arxiv.org/abs/2507.22659
- DOI: 10.1145/3815425
- Authors: Sabrina Kaniewski, Fabian Schmidt, Markus Enzweiler, Michael Menth, Tobias Heer
- Version note: v1 announced 30 Jul 2025; current version submitted 19 Dec 2025. 43 pages + 20 pages of references.
- Scope: 263 studies, January 2020 to November 2025. Taxonomy by task formulation, input representation, system architecture, technique, plus dataset coverage and diversity analysis.
- Artifacts: https://github.com/hs-esslingen-it-security/Awesome-LLM4SVD

**Use it as the corpus seed.** This is a better starting point than the earlier hand-assembled list: curated, with a maintained repo and taxonomy axes that map almost directly onto your ingestion schema. Replace the ad hoc 50-75 with a selection drawn from this, filtered by your verification rules.

### 2. LLMs in Software Security: A Survey of Vulnerability Detection Techniques and Insights (2025)

- arXiv: https://arxiv.org/abs/2502.07049
- Venue: ACM Computing Surveys, 58(5), November 2025
- Authors: Ze Sheng, Zhicheng Chen, Shuning Gu, Heqing Huang, Guofei Gu, Jeff Huang
- DOI: not confirmed in this pass. Resolve through the ACM DL record for CSUR 58(5) before citing one.

**Caveat on the Critical label.** Content overlaps entry 1 substantially, and entry 1 is larger and newer. The real value here is the venue (CSUR is the highest-prestige home in this set) and a second independent taxonomy to cross-check entry 1's categories against. If two reviews disagree about how to partition the field, that disagreement is itself a finding worth recording.

### 3. Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection (2025)

- arXiv: https://arxiv.org/abs/2508.04448
- Authors: Damian Gnieciak, Tomasz Szandala
- Head-to-head: SonarQube, CodeQL, Snyk Code versus GPT-4.1, Mistral Large, DeepSeek V3

Reported mean F1: LLMs 0.797 / 0.753 / 0.750; static tools 0.260 / 0.386 / 0.546. LLM advantage comes from recall. DeepSeek V3 has the highest false-positive ratio. All LLMs mislocate issues at line/column granularity due to tokenisation. The score-to-tool mapping is verified against Section V and Table XIII, not inferred from abstract ordering (claim D3-C01). Authors recommend a hybrid pipeline: LLM for early triage, deterministic scanners for high-assurance verification.

**This is the baseline your system must beat, and the strongest argument for your architecture.** But treat the numbers carefully: 10 real-world C# projects, 63 vulnerabilities, single configuration, no variance reported. The direction is convincing; the magnitudes are not transferable. Note also that "mislocates at line/column granularity" is a direct hit on reproduction contracts. A finding attributed to the wrong line cannot ship a valid witness, so this paper predicts a real failure mode in your pipeline.

---

## High

### 4. Outside the Comfort Zone: Analysing LLM Capabilities in Software Vulnerability Detection (2024)

- arXiv: https://arxiv.org/abs/2408.16400
- Authors: Yuejun Guo, Constantinos Patsakis, Qiang Hu, Qiang Tang, Fran Casino
- Venue: ESORICS 2024
- Method: six vulnerability-specialised open models against six general-purpose LLMs, three of them fine-tuned on a purpose-built dataset, across five state-of-the-art benchmarks.

**Highest value per page for your hard problem.** Two findings matter: fine-tuning helps small models only inside the scenarios they were trained on, and the benchmark datasets themselves contain mislabelling that corrupts training and evaluation. That second point is fatal to an unexamined ground-truth harness. If your labels are wrong, your error-correlation matrix measures label noise, and you would report that as correlated model error. Read this before building the harness in section 5 of the design review.

### 5. Large Language Model for Vulnerability Detection and Repair: Literature Review and the Road Ahead (2024, published 2025)

- arXiv: https://arxiv.org/abs/2404.02525
- Authors: Xin Zhou, Sicong Cao, Xiaobing Sun, David Lo
- Venue: ACM Transactions on Software Engineering and Methodology, May 2025
- DOI: not confirmed in this pass; resolve via ACM DL.
- Scope: 43 papers from 25 distinct venues plus 15 preprints, 58 total. Covers work through 2024.

**Demote in practice.** Correctly labelled High, but it is the oldest in this set and its coverage is superseded by entries 1 and 2. Its durable contribution is the clean split between detection adaptation and repair adaptation, which is worth keeping as a schema axis. Do not cite it for state of the art.

---

## Notes for the corpus build

1. **Version pinning matters here.** Entry 1 changed substantially between v1 and the current version. Record `version` in the existence block, not just the year.
2. **Two of three DOIs are unresolved.** Entries 2 and 5 need their ACM DOIs confirmed through the publisher record. Do not accept a DOI from a secondary citation list; several of the citations surfaced in search had garbled or partial DOI strings.
3. **The set is internally consistent.** Unlike the previous corpus, all five exist and match their described content. The risk here is not fabrication, it is over-reading magnitudes from small benchmarks (entry 3) and inheriting contaminated labels (entry 4).
4. **Entry 1's repo is the practical win.** `Awesome-LLM4SVD` is maintained and structured, which makes the ingestion job mostly a matter of filtering and verification rather than discovery.
