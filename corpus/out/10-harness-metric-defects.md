# Output 14: Harness metric defects

The harness is the part of this project that turns an argument into a measurement. Checking it after checking the validators turned up three defects that would have produced a published matrix describing something other than what the project claims.

All three are in specifications that were already marked `[D]`, so none of this contradicts a source. They are wrong anyway, and one of them is arithmetic.

---

## 1. The pilot could not produce the metric it was piloting

`S6` requires the error-correlation matrix stratified by CWE family. `S10` specified a pilot of 60 to 100 samples. Those two requirements cannot both hold.

A phi coefficient over a stratified subsample needs positives and negatives in both margins. Simulating a skewed 14-family distribution at a 10% prevalence, the fraction of strata holding fewer than one expected positive is:

| Samples | Median positives per family | Strata with under one expected positive |
|---|---|---|
| 60 | 0.3 | 88% |
| 100 | 0.4 | 74% |
| 1,000 | 4.5 | 20% |
| 5,000 | 22.2 | 7% |

*Computed in the sandbox by simulation over a Dirichlet family distribution. This is not from any source in the corpus and is not presented as a finding about the field. It is arithmetic about the plan.*

Read the middle row: three quarters of the per-CWE cells in the proposed pilot would be empty. `S6`'s amendment already says an undefined cell is reported as undefined rather than computed as 0 or 1, which prevents the worst version of this. It does not prevent a matrix that is mostly "undefined" from being summarised as a sparse result. And a prevalence of 10% is optimistic: several CWEs in D3's own coverage are rarer than that, which moves the numbers the wrong way.

**Fixed.** `S10` now runs in two stages. Stage 1 covers plumbing at 60 to 100 samples and reports pooled figures plus the count of strata it could not fill. Stage 2 supports a per-stratum claim only where a family holds at least 5 positives and 5 negatives, which is roughly 100 adjudicated samples per family at that prevalence, or a deliberate restriction to two or three families. `S6` gained the matching floor, with explicit pooling rules and a requirement to state what was suppressed.

The earlier version of `S10` was not wrong to start small. It was wrong to imply that a small pilot validates a metric whose own definition is stratified.

---

## 2. Reviewers were never required to emit a verdict

Every metric in `S6` is computed over per-sample binary error vectors. Nothing in the specification required a reviewer to produce one.

A reviewer that reports "I found three issues in this repository" has produced findings, not verdicts. For a sample it says nothing about, the error vector has no entry, and the missing entry is not neutral: it is exactly the case where a reviewer declined to decide. Filling it with "not vulnerable" invents a verdict; dropping it computes correlation over the subset where the reviewer chose to speak, which is a correlation between two reviewers' willingness to comment.

**Fixed.** `S6` requires a verdict for every sample including `clean`, and excludes any reviewer that cannot produce one.

This is the same shape as the label problem in D4. Absence of a claim is not a claim of absence, and a matrix built by conflating them measures reporting behavior while calling it error.

---

## 3. Post-gate fabrication rate is circular

`S4` defines fabrication rate as shipped findings that a maintainer rejects as non-reproducing. The gate in the same section exists to stop exactly those findings from shipping.

So the metric measures the gate's output after the gate has done its work. A system that suppresses everything scores 0%. A system whose gate works scores 0% for the same reason a broken one does, and the two are indistinguishable.

**Fixed.** Three numbers are reported together: pre-gate fabrication rate, post-gate fabrication rate, and gate pass rate. The third is what separates "the gate works" from "the gate is a wall". Recall carries the same requirement.

---

## 4. What else was checked and found sound

Recorded because a clean result is evidence too.

- **Undefined-cell handling.** The amendment to `S6` already forbids computing an empty cell as 0 or 1, and requires the count of jointly evaluated items. That was correct before this pass and remains correct.
- **The 0.8 threshold.** Correctly described as an exploratory trigger rather than a definition of independence.
- **Sample size for the metric itself.** The concern that 100 samples cannot estimate a phi at all turned out to be false. Simulating two independent reviewers with equal 80% skill gives a phi sampling standard deviation of 0.11 at 100 samples, which is adequate to detect a real correlation of 0.5. The pilot was too small for *stratification*, not for the statistic. That distinction was checked before anything was claimed about it.

---

## 5. Still wrong, and not fixed

1. **Population mismatch.** The matrix is computed on benchmark samples. The product's claims are about findings in real repositories. Per-sample labels do not exist in production, so the bridge between the measured population and the claimed one is currently an assumption. It needs at least one real-repository set with adjudicated findings, and the claim needs to be narrowed to match whatever is measured.
2. **Labels remain the weak link.** Nothing here fixes label noise; it only stops the plan from hiding it.
3. **No floor reviewer has been built.** It is specified, not implemented, and it is cheap, which makes its absence a choice rather than a constraint.
