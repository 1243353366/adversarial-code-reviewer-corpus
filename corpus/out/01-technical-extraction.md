# Output 2: Technical extraction

Five documents. All full texts retrieved and read; page/line locators held in the local source tree (`corpus/txt_*.txt`, `corpus/html_*.html`, `corpus/api.xml`). Nothing here is extracted from an abstract alone.

**Evidence tags.** `[E]` directly established by source. `[A]` author interpretation. `[I]` independently replicated (none found in this set). `[D]` derived engineering hypothesis, mine, not published. `[P]` unverified implementation proposal. `[C]` contradicted by another source in this corpus.

---

## D1: Systematic Literature Review on Detecting Software Vulnerabilities with LLMs (Kaniewski et al., 2025)

### Research questions
RQ1 to RQ5 covering approaches, task formulation, input representation, architecture, datasets and techniques `[E]`.

### Problem statement
The field has fragmented: rapid growth produced studies that are hard to compare because system designs and datasets differ, so no clear picture of state of the art exists `[E]`.

### Methodology
SLR following an established software-engineering SLR protocol. 263 primary studies from January 2020 to November 2025 in the v2 revision. Search string is reported in full, including model-name variants and a requirement that the paper combine an LLM term with a vulnerability term and a detection verb `[E]`.

### Datasets and data limitations
The dataset analysis is the most useful part for engineering. Four distinct problems, each separately evidenced:

1. **Granularity.** Detection is applied at function or slice level, driven by dataset dominance and earlier context-window limits. Even with 128K-token contexts, models perform poorly on vulnerabilities distributed across code, citing Huynh et al. 2025 `[E]`. Language coverage is skewed to C/C++ with limited Java and Python `[E]`.
2. **Labelling.** Synthetic datasets have high label precision but oversimplify. Real-world datasets are labelled by automated methods (vulnerability-fixing commits, static tools) and carry label noise and redundancy, citing Croft et al. 2023 `[E]`. Manual verification is accurate but does not scale `[E]`.
3. **Missing reasoning ground truth.** Datasets supply a label and sometimes a description, rarely a verified causal chain, so LLM reasoning quality cannot be benchmarked cheaply `[E]`.
4. **Leakage and imbalance.** Devign and Big-Vul are likely inside pretraining corpora, making standard train/test splits unreliable `[A, well-argued]`. Strong class imbalance and a long-tailed CWE distribution cause overfitting to frequent vulnerability types `[E]`.

### Technical architecture taxonomy
Task formulation, input representation, system architecture and adaptation technique. The architecture dimension includes single-agent prompting, RAG, ensembles of models or representations, and a **Controller** pattern `[E]`. Two entries matter directly to this project:

- Sayagh and Ghafari 2025 use **multiple agentic teams**: a lister searches for candidate CWEs, a reviewer requests missing CWEs, further agents fetch external code context, a final agent decides per CWE `[E, secondary citation]`.
- Farr et al. 2025 route code to automatic quarantine, cleared-for-deployment, or human analyst review, sending high-uncertainty code to humans `[E, secondary citation]`.

### Results
Seven limitations, L1 to L7: dataset and detection granularity; labelling and quality; study evaluation and comparability; up-to-date vulnerability knowledge; code and vulnerability representation; interpretability; pipeline integration `[E]`. Each has a paired actionable direction `[A]`.

### Statistical limitations
Survey-level. No meta-analysis, no pooled effect sizes, and comparability across the 263 studies is itself one of the identified problems `[E]`.

### Counterarguments and negative results
The review records that most datasets do not ship predefined train/validate/test splits, so reported numbers are often incomparable `[E]`. It records that code-processing techniques (graph, RAG, slicing) yield only modest gains that diminish on cross-file vulnerabilities `[C, tension with D2]`.

### Reproducibility
Full search protocol, living artifact repository `Awesome-LLM4SVD` `[E]`.

### Future opportunities
L1 to L7 paired directions, plus agentic self-assessment and CWE-type classifiers as explicit suggestions `[E]`.

---

## D2: LLMs in Software Security, A Survey (Sheng et al., 2025)

### Research questions
RQ1 to RQ4: LLM architectures for security tasks, benchmark and metric reliability, technique best practice, and challenges with directions `[E]`.

### Problem statement
No prior survey isolated LLM strengths and weaknesses specifically inside vulnerability detection; existing work mixed detection with malware and intrusion analysis `[E]`.

### Methodology
Structured survey around four aspects, with explicit inclusion and exclusion criteria. Restricted to C/C++, Java and Solidity; excluded traditional DL methods and non-detection security tasks `[E]`.

### Datasets and data limitations
Evaluated function-level and file-level granularity. States that repository-level datasets reflecting real development are significantly lacking, which limits generalisation to multi-file vulnerabilities `[E]`.

### Results
- Multi-agent approaches are widely used, motivated by decomposing complex detection into manageable sub-problems `[E]`.
- 41.3% of surveyed studies used code-processing techniques for context windows; gains are modest over direct prompting and diminish on complex cross-file cases `[E]`.
- Fine-tuning: large models above 10B parameters with parameter-efficient tuning achieve the best results; GPT-4 and CodeLlama reported with F1 near 0.9; discriminative strategies need at least 10K samples `[E]`.
- Four named challenges: data leakage inflating metrics; difficulty with complex code context; positional bias in large context windows causing information loss; high false positive rates and poor zero-day performance `[E]`.

### Statistical limitations
The F1-near-0.9 figure is reported across heterogeneous studies with different datasets and splits, and the survey itself flags data leakage as a general problem `[E]`, which makes such pooled numbers unsafe as a capability estimate `[D]`.

### Reproducibility
Protocol reported, living findings list maintained `[E]`.

---

## D3: LLMs Versus Static Code Analysis Tools (Gnieciak and Szandala, 2025)

### Research question
Head-to-head quantitative and qualitative comparison of three rule-based static tools against three LLMs on vulnerability detection, including latency and developer vetting effort `[E]`.

### Prior work
Notes that a single state-of-the-art analyser highlights vulnerabilities in roughly half of real-world vulnerability-contributing commits, and that false-positive noise limits adoption `[E, citing prior work]`.

### Methodology
Ten real-world C# projects with 63 embedded vulnerabilities spanning SQL injection, hard-coded secrets and outdated dependencies. SARIF 2.1.0 as the common output format so that location and rule identity are comparable. Default configurations for every tool. Uniform execution environment. Metrics: precision, recall, F1, latency, human effort to vet true positives `[E]`.

### Results
Mean F1, LLMs: GPT-4.1 0.797, Mistral Large 0.753, DeepSeek V3 0.750. Static: SonarQube 0.260, CodeQL 0.386, Snyk Code 0.546 `[E]`. The LLM advantage originates in recall `[E]`. DeepSeek V3 has the highest false-positive ratio `[E]`.

**Localization failure.** Against the SARIF `region` field, all three LLMs failed to report correct line and column. All correctly identified the file. The authors found no correlation among the errors and attribute them to BPE tokenisation `[E]`. They state this may preclude LLM use where precise location is required `[E]`.

**Fabricated staleness.** A table of hallucinated findings where the models flag currently-current library versions as outdated, and in one case attach an outdated-dependency rule to a current package `[E]`.

### Negative results
Universal localization failure. Hallucinated dependency findings. CodeQL slowest of all six systems, attributed to loading large predefined rule sets `[E]`.

### Statistical limitations
Single run per configuration, no variance, no confidence intervals, no significance tests, 63 vulnerabilities, one language. The authors do not claim generalisation beyond the suite `[E]`.

### Reproducibility
Authors state an open benchmark and a JSON result harness are released with the paper `[E]`; URL not verified in this pass.

### Provenance caveat
The discussion section refers to itself as "this thesis" `[E]`. This is a degree thesis adapted to a preprint, not a peer-reviewed publication.

---

## D4: Outside the Comfort Zone (Guo et al., ESORICS 2024)

### Research questions
Five: current methods; whether base LLMs detect vulnerabilities; whether fine-tuning is an enabling strategy; robustness; whether curation and labelling are robust enough `[E]`.

### Methodology
Six vulnerability-specialised open models against six general-purpose LLMs, three of them fine-tuned on an author-compiled dataset. Evaluated on that dataset plus five state-of-the-art benchmarks. Binary vulnerable/non-vulnerable classification. Semgrep used as an independent industrial oracle against dataset labels `[E]`.

### Datasets and data limitations
This paper's central contribution. Attributed causes of mislabelling: automated annotation tooling; treating code as fixed after a commit even where the vulnerability was not actually resolved; code sample length effects `[E]`.

### Results
- Accuracy varies significantly across benchmarks `[E]`.
- Fine-tuning lets small models beat larger ones, but only in the specific scenarios they were trained on `[E]`.
- Larger models are more stable across datasets but still not strong `[E]`.
- **Semgrep detected only a very small fragment of the vulnerabilities each dataset claims to contain** `[E]`.
- **Semgrep detected vulnerabilities inside code that datasets labelled secure, in several datasets** `[E]`.
- Answer to whether base LLMs detect vulnerabilities: recorded by the authors as **unclear** `[E]`.

### Counterarguments and negative results
Explicitly pushes back on the premise that benchmark accuracy measures detection capability `[A, supported by the Semgrep evidence]`. Notes that training on mislabelled data is functionally analogous to data poisoning `[A]`.

### Statistical limitations
Binary formulation collapses severity and type. The label-noise finding is itself unquantified: Semgrep's own recall on these samples is unknown, so "Semgrep missed it" and "the label is wrong" are not distinguished `[D]`.

### Reproducibility
Six models, five named benchmarks, an authored dataset `[E]`. Code and data availability not confirmed.

---

## D5: Vulnerability Detection and Repair, Literature Review (Zhou et al., 2024/2025)

### Research questions
Three: which LLMs are used; how LLM adaptation techniques are categorised for detection; the same for repair `[E]`.

### Methodology
58 papers: 43 published across 25 venues plus 15 preprints, covering 2018 to 2024, with enumerated exclusion criteria including "mentions LLMs only in future work" `[E]`.

### Results
Six enumerated limitations:

- **L1 Small input granularity.** Function or line level dominates; cross-function and repository-wide cases are overlooked, citing Sejfia et al. 2024 and Zhou et al. 2024 `[E]`.
- **L2 Lack of high-quality datasets.** Noisy and incorrect labels from automatic collection, including clean code labelled vulnerable `[E]`.
- **L3 Complexity in vulnerability data** degrading performance `[E]`.
- **L4 Reliance on lightweight LLMs** `[E]`.
- **L5 Lack of deployment consideration**, with GitHub Copilot cited as having IDE integration as its most-reported limitation `[E]`.
- **L6 Lack of accuracy and robustness** `[E]`.

### Technical mechanisms
Notes that Transformer architectures model sequential relations and can miss structural aspects of code, motivating combination with program analysis to extract structural features `[E]`; and the Fusion-in-Decoder partitioning approach for long functions `[E]`.

### Statistical limitations
Coverage ends in 2024 and is superseded for state of the art by D1 and D2 `[D]`.

### Reproducibility
Protocol and exclusion criteria reported; no artifact repository stated `[E]`.

---

## Cross-document synthesis

Four mechanisms recur independently across three or more documents, which is the strongest evidence available in this corpus short of replication:

1. **Ground-truth labels in this field are unreliable.** D4 demonstrates it empirically with an external oracle. D1 and D5 both name automated labelling as the cause. D2 names data leakage. `[E]`
2. **Function-level detection does not transfer to repository-level review.** D1 L1, D2, D5 L1. `[E]`
3. **LLMs trade precision for recall and cannot localize.** D3 measures both. `[E]`
4. **Reported benchmark accuracy is not a capability estimate.** D2 flags leakage, D4 shows mislabelling, D1 flags the absence of standard splits. `[E]`

None of the five reports a pairwise error-correlation statistic across multiple reviewers or models, and none reports a fabrication rate for findings. That absence is the gap this project targets. It is a claim about these five documents, not a claim about the whole literature. `[E for the five] [D for the generalisation]`
