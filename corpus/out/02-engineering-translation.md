# Outputs 3, 4 and 5: Repository relevance map, implementation opportunities, tests and benchmarks

Every item carries an evidence tag. Per the protocol's third rule, nothing here is presented as a published research finding unless tagged `[E]`. Items tagged `[D]` or `[P]` are my engineering hypotheses and carry no research authority.

Component names used below correspond to the target system: **Corpora** (ingestion, retrieval, claim-level evidence store), **Reviewer Core** (multi-model review, refutation, adjudication), **Harness** (ground truth, metrics, calibration), **CloudSentry** (dependency and supply-chain analysis).

---

## Repository relevance map

| Finding | Source | Component | Why it lands there |
|---|---|---|---|
| All LLMs fail SARIF line/column localization; errors uncorrelated, attributed to BPE tokenisation | D3 `[E]` | Reviewer Core, finding schema | A finding whose location cannot be trusted cannot carry a reproducible witness keyed to line numbers |
| Models flag current library versions as outdated | D3 `[E]` | CloudSentry, dependency claims | Dependency claims are model-knowledge claims unless resolved against a live advisory source |
| Semgrep, as an external oracle, contradicted dataset labels in both directions | D4 `[E]` | Harness | Ground truth needs an oracle, not a label field |
| Mislabelling causes: automated annotation, unresolved-vulnerability commits, sample length | D4 `[E]` | Harness, Corpora | Determines where in the pipeline to insert label verification |
| Devign and Big-Vul likely inside pretraining corpora; standard splits unreliable | D1 `[A]`, D2 `[E]` | Harness | On a public repo, memory and analysis are indistinguishable without a contamination control |
| Strong class imbalance and long-tailed CWE distribution | D1 `[E]` | Harness | Aggregate metrics will be dominated by frequent CWEs unless stratified |
| Function-level detection does not transfer to repository-level review | D1, D2, D5 `[E]` | Reviewer Core scope | Public-repo review is the under-served and hardest setting; the literature predicts poor transfer |
| Code-processing techniques give modest gains that shrink on cross-file vulnerabilities | D2 `[E]`, D1 `[E]` | Reviewer Core retrieval | Argues against naive whole-repo context stuffing |
| Positional bias in long context windows causes information loss | D2 `[E]` | Corpora retrieval | Retrieval and slicing design constraint |
| Agentic multi-team review with lister, reviewer and context-fetching agents already published | D1 `[E]`, secondary citation | Reviewer Core novelty positioning | Directly relevant to the novelty claim |
| Uncertainty-gated routing of code to human analysts already published | D1 `[E]`, secondary citation | Reviewer Core | Cheaper than full automation and already established |
| Datasets rarely provide verified reasoning chains, so reasoning quality cannot be benchmarked | D1 `[E]` | Corpora, Reviewer Core | Motivates capturing reviewer rationale in a structured, checkable form |
| No pairwise error-correlation statistic in any of the five documents | D1-D5 `[E]` | Harness | The measured gap this project exists to fill |
| Self-hosting SonarQube Community avoids sending code to a third party; commercial model choice raises privacy exposure | D3 `[E]` | All | Model and tool selection is a data-residency decision, not just a quality one |

---

## Implementation opportunities

### S1. Content-anchored findings instead of line-anchored findings

**Mechanism.** An LLM's reported line and column are unreliable because tokenisation does not preserve character offsets precisely `[E, D3]`.
**Capability improved.** Reproducibility of every finding.
**Component.** Reviewer Core, finding schema.

**Spec.** A finding must carry: normalized enclosing function signature, AST node hash, a 3-line context window with whitespace normalized, and the commit SHA. Line numbers are advisory metadata, resolved at display time by matching the content anchor against the checkout. A finding whose anchor does not resolve is rejected before review, not after.

**Acceptance criteria.**
- 100% of findings emitted into the pipeline carry a valid content anchor.
- Anchor resolution rate on an unchanged checkout: at least 99%.
- After injecting a 5-line offset and unrelated refactors in the same file, resolution rate stays at least 95%.

**Security and privacy.** Anchor text is code; treat it as untrusted and never re-interpolate it into a prompt without escaping.
**Tests.** Line-shift invariance; reformat-only commit; function renamed but body identical; function moved between files (expected to fail resolution, and must fail loudly).
**Limitations.** Does not fix the deeper problem that the model may have identified the wrong construct; it only makes the reference stable. An alternative explanation for D3's localization errors is that models were locating a different, also-suspicious region rather than failing arithmetically. `[D]`

---

### S2. Contamination probe

**Mechanism.** Public benchmarks are plausibly inside pretraining corpora, so accuracy can reflect recall `[E, D1/D2]`.
**Capability improved.** Whether a finding reflects analysis or memory.
**Component.** Harness.

**Spec.** Maintain three evaluation sets: (a) real public repos with known findings, (b) the same repos with program-preserving mutations that move the vulnerability across a function boundary, (c) repositories created after the model's training cutoff. Report performance on each separately.

**Acceptance criteria.**
- Report a contamination delta: recall(a) minus recall(b), with a bootstrap confidence interval.
- If the delta exceeds 15 percentage points, the reviewer is flagged as recall-dependent and its findings are labelled accordingly in output.

**Tests.** Cutoff-dated repo set; mutation generator that preserves compilability; held-out set never used during prompt development.
**Limitations.** Cutoff dates are not reliably published per model version; set (c) will be small for recent models. This cannot prove contamination, only bound its effect. `[D]`

---

**Amendment (remediation).** The three-set comparison has a confound. A vulnerability moved across a function boundary may be harder to detect because it is harder to analyse, not because the original detection came from memory, so a recall drop cannot establish contamination by itself. Required additions: (a) an unchanged-code control scored by the same reviewer in the same run, separating mutation difficulty from corpus exposure; (b) a semantics-preserving transformation that does not move the vulnerability, separating presentation effects from cross-boundary effects; (c) an independent check that each mutant is behaviourally equivalent to its original, since a mutant that changes behaviour is a different program; (d) a separate mutation-difficulty measurement, such as tool or human success rate on the mutated set. Contamination is reported as a hypothesis supported by converging signals, never as a binary verdict. The 15-point threshold is a placeholder until calibrated against those controls; publishing it as a decision rule first would manufacture precision the experiment does not have.

---
### S3. Label provenance with cross-oracle adjudication

**Mechanism.** An external static oracle disagreed with existing labels in both directions across five standard benchmarks `[E, D4]`.
**Capability improved.** Validity of every downstream metric.
**Component.** Harness, Corpora.

**Spec.** Per sample: record labelling source (CVE fix commit, synthetic injection, human, model), oracle verdicts from at least two independent engines, disagreement flag, and a human adjudication record. No sample enters the harness with a single-source label unless it is synthetically injected.

**Acceptance criteria.**
- 100% of ground-truth samples carry a labelling source.
- 100% carry at least two oracle verdicts, or an explicit `human_verified` record.
- Publish the oracle disagreement rate per CWE. Do not hide it.

**Tests.** Inject known mislabels and confirm they are caught; re-label a sample subset blind and measure inter-rater agreement.
**Limitations.** D4 does not establish that Semgrep is correct, only that it disagrees `[D]`. Two-oracle agreement is not truth, it is a weaker claim and must be described as such. Alternative explanation for D4's finding: Semgrep's rules simply do not cover these samples, making "mislabelling" and "tool gap" observationally equivalent without manual review. `[D]`

---

### S4. Deterministic verification gate

**Mechanism.** LLMs gain recall but cost precision, and the authors recommend a hybrid: LLM early triage, deterministic scanners for high-assurance verification `[E, D3]`.
**Capability improved.** Fabrication rate.
**Component.** Reviewer Core.

**Spec.** Three claim classes with different bars. `refuted` (a deterministic tool or test contradicts it) never ships. `verified` (reproduced by an executable artifact) ships. `unverified_suspicion` ships only in an explicitly labelled internal stream and is never counted as a finding.

**Acceptance criteria.**
- Zero findings in the shipped stream without evidence matching its category, per the contract table below.
- Fabrication rate, defined as shipped findings that a maintainer rejects as non-reproducing, reported with a Wilson 95% interval and kept below a stated threshold agreed before the first benchmark run, not after.

**Tests.** Canary set of deliberately plausible-but-false findings (see S5's stale-dependency class, which D3 supplies as a real example `[E]`); adjudicator blind test.
**Limitations.** A deterministic tool cannot verify architecture, design or logic-class findings, so this gate suppresses a whole category of review output. That is a deliberate trade and should be stated in the product, not hidden. `[D]`

---

**Amendment (remediation).** The single reproduction bar was too strong. It is correct for exploitable vulnerabilities and wrong for the rest of the product's output, and a gate that cannot be met for architecture or logic findings does not raise quality, it deletes a category and calls the silence rigor. Evidence contracts by category:

| Finding category | Acceptable evidence |
|---|---|
| Exploitable vulnerability | Reproducer or execution witness |
| Static security defect | Analyzer witness (rule id plus matched path) or verified data-flow path |
| Logic defect | Counterexample or failing property test |
| Reliability | Fault-injection trace or failure log |
| Architecture | Dependency or control-flow evidence naming the coupling |
| Maintainability | Specific location plus the criterion violated |

Two rules keep the loosening honest. First, each contract must be as hard to fabricate as a reproducer: an analyzer witness means a rule id and a matched path that a second party can re-run, not the analyzer's assertion. Second, `unverified_suspicion` remains a separate stream and is never counted in any metric that reports findings.

---
### S5. Advisory resolution for dependency claims

**Mechanism.** Models asserted that current package versions were outdated, and applied an outdated-dependency rule to a current package `[E, D3]`. Static tools do not make this error because their deprecation lists are maintained and updated `[E, D3]`.
**Capability improved.** Trustworthiness of the most common false claim class in the benchmark.
**Component.** CloudSentry.

**Spec.** A dependency or staleness claim is a *lookup*, not a model judgement: resolve the version against an advisory database and the registry's current version at review time. The model may flag a candidate; only the lookup can assert it.

**Acceptance criteria.**
- 100% of dependency claims carry a registry or advisory record locator and a timestamp.
- Zero shipped dependency claims that contradict the registry state at review time.

**Tests.** The three hallucinated cases in D3's table, replayed as regression tests. A repo pinned to the latest release of every dependency must produce zero staleness findings.
**Limitations.** Advisory databases lag disclosure; "not in the database" is not "safe" and must be rendered as unknown, never as clean. `[D]`

---

**Amendment (remediation).** Three conditions were conflated and must be reported separately, each with its own evidence source and timestamp: `outdated` (installed version older than the latest release), `known_vulnerable` (installed version carries a published advisory), `unsupported` (installed version outside its maintenance window), and `unknown` where no source settles it. A current release can be vulnerable; an older release can be perfectly safe inside support. Version age is not evidence of vulnerability, and advisory presence is not evidence of current exposure.

---
### S6. Error-correlation matrix and fabrication rate as primary metrics

**Mechanism.** None of the five documents reports pairwise reviewer error correlation `[E]`; ensemble and voting approaches are documented without such measurement `[E, D1]`.
**Capability improved.** Whether the ensemble is real or decorative.
**Component.** Harness.

**Spec.** For each reviewer pair, compute the phi coefficient over per-sample binary error vectors, stratified by CWE family (S7), with bootstrap intervals. Publish the matrix in the repository README, not an appendix.

**Acceptance criteria.**
- Every reviewer pair reported, including high correlations.
- Any pair above 0.8 is marked as a single effective reviewer and the ensemble size is restated accordingly.
- Fabrication rate published alongside recall. Neither reported alone.

**Tests.** Sanity check by feeding the same reviewer twice under two prompts: correlation must approach 1.0, validating that the metric detects duplication.
**Limitations.** Phi on imbalanced classes is unstable, which is why stratification matters. Error correlation also conflates shared blindness with shared knowledge; the metric bounds ensemble value without explaining it. `[D]`

---

**Amendment (remediation).** Phi is undefined when either error vector has zero variance, which happens whenever a reviewer makes no errors on the evaluated set. That cell is reported as undefined, never computed as 0 or 1. Every pairwise figure carries the number of jointly evaluated items, a bootstrap confidence interval, the raw error-overlap count, and a per-class breakdown, because class balance and sample size both vary by stratum. The 0.8 alert threshold is an exploratory trigger for inspection, not a definition of independence, and must not be described as one in any report that quotes it.

---
### S7. CWE-stratified reporting

**Mechanism.** Long-tailed CWE distribution causes models to overfit frequent types and fail rare ones `[E, D1]`.
**Capability improved.** Honest capability claims.
**Component.** Harness.

**Spec.** All metrics reported per CWE family with sample counts. Aggregate numbers require the per-family table to be published alongside.

**Acceptance criteria.** No aggregate metric appears without its stratified breakdown and an explicit note of which families had too few samples to report.
**Tests.** Confirm that aggregate recall is arithmetically consistent with the stratified table.
**Limitations.** Stratification reduces sample size per cell; with 63 vulnerabilities in D3's suite, per-CWE cells are too small to support any conclusion, which is itself worth publishing as a constraint. `[E for the constraint] [D for the recommendation]`

---

### S8. Uncertainty-gated human routing

**Mechanism.** Published routing of code by model uncertainty to automatic quarantine, deployment clearance, or human analyst review `[E, D1, secondary citation of Farr et al. 2025]`.
**Capability improved.** Cost and risk profile of the whole system.
**Component.** Reviewer Core.

**Spec (superseded below).** Emit a three-way disposition per finding: auto-clear, human review, quarantine. Quarantine blocks the automated path and never resolves without a human. **This line is retained only as the record of what was originally specified; the amendment at the end of this section withdraws `auto-clear`, and no part of this repository should implement the three-way form.**

**Acceptance criteria.** 100% of quarantined items have attribution to the triggering reviewer and the uncertainty signal; measured abstention rate reported.
**Tests.** Feed a set of known-ambiguous findings and confirm routing stability across repeated runs.
**Limitations.** This is a design pattern from the literature, not a validated policy. Whether uncertainty signals are calibrated for code review is unknown and is itself an open question. `[D]`

---

**Amendment (remediation).** Automatic clearance is withdrawn from the default policy. The corpus records that uncertainty signals are not calibrated for code review, which makes routing on them circular: an uncalibrated confidence measure would decide whether a human must inspect the conclusions that the same measure produced. Until calibration is demonstrated against a reliability curve on the harness, exactly two dispositions are supported: `human_review` and `quarantine`. `auto_clear` returns only when a published calibration study shows the abstention threshold holds on held-out code, and no repository is ever certified secure by this system. This binds hardest in CI/CD, where a wrong clearance ships a vulnerability.

---
### S9. Structured reviewer rationale as reasoning ground truth

**Mechanism.** Datasets rarely contain a verified root-cause chain, making LLM reasoning quality expensive to benchmark `[E, D1]`.
**Capability improved.** Evaluability of the refutation protocol.
**Component.** Corpora, Reviewer Core.

**Spec.** A reviewer must emit a mechanism chain: source of untrusted input, transformation, absence or failure of a guard, sink, and the falsification condition it pre-registers. Store chains, and where a human resolves an adjudication, store the human's chain as labelled ground truth. This builds the reasoning corpus the field is missing.

**Acceptance criteria.** 100% of shipped findings carry a complete chain; adjudication outcomes accumulate as paired human chains at a rate sufficient to report on.
**Tests.** Chain completeness validator; measure whether pre-registered falsification conditions predicted the actual adjudication outcome.
**Limitations.** Self-reported chains are post-hoc rationalizations until validated; that is precisely why the adjudication-paired subset is the only trustworthy part. `[D]`

---

## Benchmark recommendations

1. **Baseline against D3's configuration** so results are comparable, while stating its limits: 10 C# projects, 63 vulnerabilities, single run, no variance. Do not quote its F1 magnitudes as targets. `[E for the numbers, D for the caveat]`
2. **Report the static-tool floor.** On the same suite, static tools scored 0.260 to 0.546 F1 `[E]`. A reviewer that cannot beat a rule-based scanner on recall has no product justification.
3. **Add a stale-dependency canary set** built from D3's hallucination table. It is a cheap, verified fabrication detector. `[E for the cases, D for their use as canaries]`
4. **Never evaluate only on Devign or Big-Vul** without a contamination discussion `[E, D1/D2]`.
5. **Publish the harness before the results**, so the acceptance thresholds predate the numbers. This is the only structural defence against the incentive problem the field already has. `[D]`

---

## Security and privacy implications

- **Repository content is attacker-controlled.** None of these five documents addresses prompt injection through code comments, fixtures or manifests. This risk is real and specific to reviewing public repositories, but it is **not** supported by this corpus and must be treated as an unverified engineering concern. `[P]`
- **Model choice is a data-residency decision.** D3 notes that one model offers significant cost benefits at the expense of increased privacy risk, and that self-hosting a static analyser's community edition avoids sending code to a third party `[E]`. Any reviewer pipeline that sends proprietary code to a hosted model needs an explicit policy.
- **Exploit publication.** A public repo publishing reproducible witnesses against unpatched OSS code is a disclosure problem, not only a licensing one. `[D]`
- **Attribution in output.** Findings generated from a corpus must not restate a paper's claim as the system's own finding. Enforce at the schema level: every claim field carries a source id or is marked `derived`. `[D]`
