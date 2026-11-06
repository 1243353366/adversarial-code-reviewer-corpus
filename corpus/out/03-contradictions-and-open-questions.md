# Outputs 6 and 7: Contradictory findings and unresolved research questions

---

## Part A: Contradictory findings

### C1. Does fine-tuning improve vulnerability detection?

- **D4** `[E]`: fine-tuning lets small models outperform larger ones, **but only within the specific scenarios they were trained on**, and models do not generalise to different testing environments.
- **D2** `[E]`: large models above 10B parameters with parameter-efficient tuning achieve optimal results, with F1 near 0.9 reported for base models like GPT-4 and CodeLlama.

**Assessment.** Surface contradiction, partially reconcilable. D2 pools results across heterogeneous studies using their own benchmarks; D4 measures cross-benchmark transfer directly. Both can be true: fine-tuning gains in-domain and degrades out-of-domain. But the two licence opposite engineering decisions (invest in a fine-tuned specialist versus invest in a general model plus architecture), so the disagreement is real for anyone building a system. `[D]`

**Unresolved because:** D2 does not report out-of-domain transfer for its near-0.9 figures, and D4 does not test at the 10B+ scale with PEFT. Neither tests the same model on the same split.

### C2. How capable are static analysis tools, really?

- **D3** `[E]`: three industry static tools scored mean F1 of 0.260, 0.386 and 0.546 against LLMs at 0.750 to 0.797.
- **D4** `[E]`: Semgrep identified vulnerabilities inside code that datasets had labelled secure, across several datasets.

**Assessment.** Direct tension in interpretation. If a static tool reliably finds vulnerabilities that labelled "clean" code contains, then D3's static F1 floor is partly a measurement artifact of its own ground truth, and its LLM-over-static margin is overstated. D3's suite is hand-curated with explicit injected vulnerability categories, which may favour tools tuned for those categories, in either direction. `[D]`

**Unresolved because:** neither paper validates its ground truth with a third method. D3 trusts its curated labels; D4 trusts Semgrep as an oracle while acknowledging Semgrep's own coverage limits.

### C3. Where should effort go: bigger models or better architecture?

- **D2** `[E]`: performance gains from larger models tend to outweigh gains from code-processing techniques.
- **D1** `[E]`: a substantial share of the field is investing in architecture (controllers, agentic teams, ensembles, retrieval) and offers a taxonomy built around it.

**Assessment.** Priority disagreement, not factual contradiction. D2's claim is about the marginal return on code processing at a given model scale; D1 documents where the field is actually spending effort. Both are consistent with a world where architecture matters most when model capability saturates. `[D]`

### C4. Does LLM vulnerability detection work at all?

- **D4** `[E]`: the authors record the answer as **unclear**.
- **D2, D3** `[E]`: report F1 near 0.9 and 0.79 respectively.

**Assessment.** This is the corpus's most important disagreement, and it is explained by measurement, not by capability. D4 attacked label validity directly and found labels wrong in both directions; D2 and D3 report accuracy against labels they did not independently verify. The plausible reading is that the performance figures in D2 and D3 are upper bounds whose headroom is set by label error and pretraining contamination. That reading is my interpretation, not any author's. `[D]`

### C5. Internal bibliometric disagreement

- **D1** `[E]`: 263 studies, January 2020 to November 2025.
- **D5** `[E]`: 58 papers, 2018 to 2024.
- **D2** `[E]`: coverage to early 2025, no single total stated.

**Assessment.** Coverage windows differ, but the gap is too large to be explained by time alone, which means inclusion criteria differ substantially between reviews of the same field. Any "the literature says" claim built on one review without checking the other is unstable. `[E for the counts, D for the inference]`

---

## Part B: Unresolved research questions

Ordered by how much they block this project.

1. **Is there any contamination-resistant evaluation protocol for LLM code review?** D1 identifies leakage as a structural problem; no document in this set proposes a remedy beyond using post-cutoff data. This is the single largest threat to every capability claim the project will make. `[E for the problem]`

2. **Can ground truth be established without expensive human adjudication?** D4 shows cross-oracle disagreement is detectable. It does not show that disagreement resolution approaches truth. Whether a two-oracle-plus-tiebreak protocol reaches useful accuracy is unknown. `[E for the setup] [D for the question]`

3. **What is the actual error-correlation structure of reviewers built on the same base model?** None of the five measures it. The whole premise of a multi-reviewer design depends on the answer, and it is currently assumed rather than known. `[E for the absence]`

4. **Does mutual refutation reduce fabrication, or merely move it?** A refuting reviewer can fabricate a refutation. No document here measures refutation quality as a separate quantity from detection quality. `[D]`

5. **Are uncertainty signals calibrated for code review?** D1 reports uncertainty-gated human routing as published practice. Whether the uncertainty estimates used are calibrated, and on what population, is not established. `[E for practice] [D for the gap]`

6. **Is the localization failure fundamental?** D3's BPE-tokenisation explanation is the authors' attribution, explicitly hedged ("likely caused by"). They also state they found no correlation among the errors, which is odd for a systematic tokenisation artifact and suggests an alternative cause. Whether the failure is a prompt-format problem, a tokenisation problem, or a model-attention problem is unresolved. `[E for the observation, A for the cause, D for the alternative]`

7. **Does any benchmark exist for repository-level, cross-file vulnerabilities with verified labels?** D1 and D2 both state the gap. No document here points to a solution, which is a notable finding given D2 says repository-level work is the field's weakest area. `[E]`

8. **What does human adjudication actually cost per finding?** D3 measures "developer effort to vet true positives" but does not report a per-finding cost that would transfer outside its suite. Any economic argument for this project is currently unsupported. `[E for the metric, D for the transfer claim]`

9. **Does feeding adjudication outcomes back into a reviewer create the same contamination it is meant to detect?** If human-resolved findings become training or prompt material, the reviewer's measured performance on those findings stops being informative. No document addresses this loop. `[D]`

10. **What are the disclosure norms for a public adversarial review system?** Nothing in this corpus addresses publishing reproducible vulnerabilities against live open-source projects. This is a policy gap, not a research gap, and it must be decided before any public release. `[D]`
