# Output 13: Oracle and pilot defects

This pass started as a naming question and turned into an audit of two things the architecture depends on and had never specified precisely: what counts as an oracle, and what happens between "harness planned" and "matrix published".

The naming question first, because it is the same failure the rest of the repository is about.

---

## 1. The status check was named inconsistently

The README said branch protection required the `validate` check. The protection API says the required context is `corpus`. Both statements were about the same thing, and only one of them was true.

- `validate` is the **workflow** name, declared at the top of `.github/workflows/validate.yml`.
- `corpus` is the **job** name inside it.

GitHub registers required status-check contexts by job name. So protection is configured against `corpus`, while the Actions tab shows a run called `validate`. A requirement set to the workflow name matches no context and is never satisfied: the pull request displays green checks and the merge stays blocked.

**Fixed.** The README now says `corpus` in both places and explains the distinction.

There is a second, worse lesson in the same episode. This repository's first blocked merge failed with:

```
Required status check "corpus" is expected.
```

`corpus` had already passed twice on that commit. The real cause was `strict: true` with the branch behind base, so the checks GitHub was waiting for belonged to a merge commit that did not exist yet. The message named the check and the problem was the branch, which sent the investigation in the wrong direction for one round trip. Error messages about controls are as capable of being wrong as the controls.

---

## 2. Oracle defects

### 2.1 Human review was listed as an oracle

`05-absurdity-lane.md` gave `oracle_binding` the values `semgrep-rule | unit-test | manual-review | none`. `manual-review` is not an oracle. It is not executable, not repeatable, and cannot be re-derived from the artifact afterwards, which is the entire test the document sets two paragraphs above it. The record format was contradicting the rule it was written to enforce.

**Fixed.** `manual-review` is removed. Adjudication is a separate field, `adjudication`, explicitly not an oracle.

### 2.2 The enum was not an enum

`oracle_binding` was a pipe-delimited string inside a JSON example. Nothing validated it, so any value passed, and a reader would reasonably assume the constraint was real. This is the `schema_version` failure again at field scale: a format that looks enforced and is decorative.

**Fixed.** It is now an object with a closed `kind` enum and a closed `verdict` enum.

### 2.3 An oracle verdict had no identity

No field recorded which oracle version or ruleset produced a verdict. An oracle is not a constant. Semgrep rules change, type checkers change, property-test harnesses change, and a `confirmed` from last quarter may not be re-derivable this quarter.

That matters more here than in most projects. The deliverable is a pairwise error-correlation matrix. A silently drifting oracle changes the error profile of one reviewer over time and would appear as a change in correlation, attributed to the model.

**Fixed.** `oracle_version` and `ruleset_hash` are required fields.

### 2.4 What was checked and found consistent

The corpus does **not** overclaim oracle verdicts as truth. `02` S3 states plainly that two-oracle agreement is weaker than truth, and that D4 establishes disagreement rather than Semgrep's correctness. `03` records that neither paper validates ground truth with a third method. No contradiction found; recorded because a clean result is also evidence.

---

## 3. Pilot defects

The plan went from specifying the harness (S3, S4, S6) to publishing an error-correlation matrix with nothing in between. Three problems followed from that gap.

**No pilot at all.** The first matrix would have run on unverified labels, which the corpus itself says measures label noise. D4 is the evidence: an industrial oracle disagreed with benchmark labels in both directions, so a disagreement between reviewers can be a disagreement about a wrong label.

**No pre-registered decision rule.** S4 requires that acceptance thresholds predate results, and then the experiment itself had no such rule. Thresholds chosen after seeing the numbers are the incentive problem this project criticises in its own sources.

**No control cell as a gate.** S6 defines a same-reviewer-duplicated control whose correlation must approach 1.0. It was defined as a row in a table, not as a condition on publishing anything.

**Fixed** in new section `02` S10: one benchmark, 60 to 100 samples, two oracles with identity fields, two reviewers, pre-registered analysis, three ordered acceptance criteria, and a kill criterion that takes the matrix down if the control cell fails.

---

## 4. Still not enforced

These remain prose, and are listed rather than implied:

1. **No schema file** validates a hypothesis record. The JSON block in `05` is a contract by convention only. It cannot be enforced while no hypothesis record exists to validate, and inventing an empty one to have something to check would be theatre.
2. **Oracle version pinning is not checked.** `oracle_version` and `ruleset_hash` are now required fields, but nothing verifies that a verdict was produced by the version recorded.
3. **The pilot has no data.** S10 specifies it. Nothing has been run.

A validator can enforce shape. Only a run enforces an experiment.
