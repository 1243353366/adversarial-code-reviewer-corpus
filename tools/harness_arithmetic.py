#!/usr/bin/env python3
"""Regenerates the stratification arithmetic quoted in 02 S6/S10 and 10 section 1.

Deterministic: fixed seed, fixed iteration count. If the quoted table and this output
disagree, one of them is stale, and tools/repro.py R12 fails.

Not a research finding. This is arithmetic about the plan: how many positives a per-CWE
stratum holds at a given sample size and prevalence.
"""
import random
import statistics

SEED = 11
ITERATIONS = 2000
FAMILIES = 14          # the CWE families D3 covers
PREVALENCE = 0.10      # optimistic for benchmark samples
ALPHA = 0.7            # skewed family distribution


def dirichlet(alpha: float, k: int) -> list[float]:
    xs = [random.gammavariate(alpha, 1) for _ in range(k)]
    total = sum(xs)
    return [x / total for x in xs]


def main() -> None:
    random.seed(SEED)
    print("| Samples | Median positives per family | Strata with under one expected positive |")
    print("|---|---|---|")
    for n in (60, 100, 1000, 5000):
        medians, empty = [], []
        for _ in range(ITERATIONS):
            weights = dirichlet(ALPHA, FAMILIES)
            positives = [w * n * PREVALENCE for w in weights]
            medians.append(statistics.median(positives))
            empty.append(sum(1 for p in positives if p < 1) / FAMILIES)
        print(f"| {n} | {statistics.median(medians):.1f} | {statistics.mean(empty) * 100:.0f}% |")


if __name__ == "__main__":
    main()
