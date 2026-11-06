# Output 9: The absurdity lane

Design specification for a hypothesis-generation lane built on the useful properties of absurd humor, kept architecturally separate from verification.

Status: `[D]` derived design. Nothing in the five-source corpus supports or refutes it. The five properties are the project brief; the mapping to operators, the output contract, the gates and the metrics are mine. This document proposes an experiment, not a capability.

---

## 1. The one constraint everything else depends on

An irreverent generator and a rigor-preserving verifier are compatible only if information flows one way.

**The absurdity lane may produce hypotheses. It may never produce findings, scores, priorities, or evidence, and it may never grade another reviewer.** If it can touch the verifier, the verifier stops being independent and every correlation metric in the project becomes uninterpretable, because you can no longer separate "the system found something" from "the system talked itself into something."

That is the whole design in one line. The operators below are the easy part.

---

## 2. The five properties, as operators

Each property becomes a mechanical transform over a fixed input artifact. Vague instructions like "be irreverent" produce nothing reproducible; each operator must emit a record that a second party could re-run.

### O1. Incongruity → misfit detection

*Notice when something does not fit.*

**Transform.** Compare an artifact against its siblings, not against a rule. Take the set of functions in a module, or the set of endpoints in a router, and ask what one member does that the others do not. The framing that makes this sharp: *which line here looks pasted in from a different codebase?*

**What it surfaces.** Missing authorization check on one of nine handlers. One endpoint that logs the request body when the others do not. A retry loop with a different backoff constant that happens to skip the rate limiter.

**Why it works without humor.** This is differential review, a known technique. The absurd framing adds the discipline of not assuming the anomaly is intentional.

**Falsification test.** Enumerate the differing dimension, then write the check that would prove the difference is unsafe.

### O2. Expectation violation → invariant inversion

*Challenge what the reviewer assumes should happen.*

**Transform.** Extract every implicit precondition the code relies on, then assume its negation. Preconditions worth extracting, in this order: input already validated, caller already authenticated, value never null, config always present, this path only reachable from the UI.

**Sharpened framing.** *Assume the caller is a malicious intern with production access and a grudge.*

**What it surfaces.** Trust-boundary mistakes that survive because the code is coherent under the intended caller. This is where most real repository-level findings sit, and repository-level review is the field's documented weak point (D1, D2, D5 all `[E]`).

**Falsification test.** Construct the call path that violates the precondition, or prove no such path exists.

### O3. Reframing → stakeholder rotation

*Look at the same behavior from an unexpected perspective.*

**Transform.** Re-describe the artifact in a domain with different success criteria, then ask which property breaks. Useful frames: a billing meter (does every action get counted exactly once?), a rate limiter under adversarial load, a data-retention policy, a court exhibit (can this be reconstructed from logs six months later?), a physical lock, a consent form (can consent be withdrawn, and is scope clear?).

**What it surfaces.** Double-spend and idempotency bugs under the billing frame. Missing revocation and over-broad scope under the consent frame. Audit gaps under the exhibit frame.

**Cost note.** This operator is the cheapest to run and the most prone to producing elegant nonsense. Enforce the falsification clause hard here.

### O4. Associative thinking → cross-finding graft

*Connect vulnerabilities that ordinarily appear unrelated.*

**Transform.** Take two existing records, from different files or different reviewers, and force the composition question: *can A's precondition create B's exploitability?*

**What it surfaces.** Chains: open redirect plus cache poisoning; token-in-URL plus referrer leakage; permissive CORS plus an authenticated JSON endpoint; a file-upload path plus a path-traversal in a different service. Chains are the highest-value output a multi-reviewer system can produce, because a single reviewer looking at one file structurally cannot see them.

**Requires.** A finding graph with anchors (see `02-engineering-translation.md`, S1), or the graft has nothing to join.

**Falsification test.** Build the chain end to end, or show the intermediate precondition cannot hold.

### O5. Irreverence → sacred-cow audit

*Do not grant code, authors, conventions, or established assumptions automatic respect.*

**Transform.** List the propositions the codebase treats as settled, then require a test for each. Typical entries: the framework escapes output, the ORM parameterizes queries, this service is internal-only, the gateway enforces auth, this dependency is maintained.

**Sharpened framing.** *A convention is a rumor until a test proves it.*

**Hard boundary.** Irreverence applies to assumptions. It never applies to verified evidence. Re-litigating an oracle result because it feels inconvenient is not irreverence, it is regression, and it is the failure mode most likely to destroy the project's credibility. Enforce with an explicit rule and an audit log, not guidance.

---

## 3. Output contract

Every operator emits a hypothesis record. There is no other output type.

```json
{
  "id": "H-0007",
  "operator": "incongruity",
  "artifact_anchor": { "function": "...", "content_hash": "...", "commit": "..." },
  "assumption": "the precondition or convention being challenged",
  "incongruity": "what does not fit, stated concretely",
  "reframing": "the frame applied, if any",
  "falsification_test": "the executable check that settles it",
  "oracle_binding": {
    "kind": "static-analysis",
    "oracle_id": "semgrep",
    "oracle_version": "1.90.0",
    "ruleset_hash": "sha256 of the rule bundle",
    "verdict": "not_run"
  },
  "adjudication": "human review record, if any; not an oracle",
  "status": "hypothesis",
  "lane": "absurdity"
}
```

**`oracle_binding` was a pipe-delimited string in an earlier draft, and it was wrong twice.** A string that looks like an enum is not one: nothing validated it, so any value passed. It also listed `manual-review` as an oracle, which contradicts the rule at the top of this document and in the audit that only an *executable* oracle makes a finding checkable. Human review is adjudication, recorded separately. It is not repeatable from the artifact and cannot be re-derived later, so it cannot carry the weight of a verdict.

`oracle_version` and `ruleset_hash` are required because a verdict without them is not reproducible. Rulesets change; a `confirmed` from last quarter may not be re-derivable this quarter, and a silently drifting oracle would corrupt exactly the pairwise correlation this project exists to measure. `verdict` is a closed enum: `not_run`, `confirmed`, `refuted`, `inconclusive`. `inconclusive` is not a soft finding, it is a counted non-result.

**`status` is a closed enum with one legal value here.** Promotion past `hypothesis` requires the deterministic gate in S4: a reproducer, or an oracle verdict. The lane cannot self-promote, and cannot annotate severity, confidence or priority.

**Rejected records are evidence.** A hypothesis with no executable falsification test is discarded and counted. The discard rate is a quality signal for the operator, not a failure to hide.

---

## 4. Metrics

Reported alongside the existing error-correlation matrix, not instead of it.

| Metric | Definition | Why it matters |
|---|---|---|
| Seeded yield | Share of shipped findings whose record traces to a lane hypothesis | Whether the lane contributed anything at all |
| Incremental recall | recall(sober ∪ lane) − recall(sober), with bootstrap CI | The only claim worth making |
| Premise error rate | Share of lane hypotheses whose stated premise was false | Fabrication risk specific to this lane |
| Premise error rate, sober lane | Same measure on the sober reviewers | Baseline; if equal, the lane is not special, it is just noisier |
| Duplication rate | Share of lane hypotheses a sober reviewer already produced | Whether association adds reach or just latency |
| Discard rate | Share of records rejected for lacking a falsification test | Novelty-theater detector |
| Cost per confirmed finding | Total lane spend ÷ verified findings seeded by it | Whether it survives contact with a budget |
| Lane-sober correlation | Phi over confirmed findings, per reviewer pair | Extends the pairwise matrix; if ~1.0 the lane is decorative |

**Pre-registration.** Thresholds for incremental recall, duplication and premise error are fixed before the first run and published with the harness. Setting them after seeing results is the exact failure this project exists to avoid.

---

## 5. Failure modes

1. **Fabrication amplification.** More hypotheses means more chances that one sounds right. This is the dominant risk and the reason for the one-way constraint in section 1. Mitigation: nothing ships without an oracle.
2. **Novelty theater.** Reframings that are clever, memorable, and unfalsifiable. Mitigation: no falsification test, no record; report the discard rate.
3. **Premise smuggling.** A false premise dressed as an insight ("assume the cache is shared across tenants") generates a confident, wrong hypothesis. Mitigation: the premise is a named field, so it can be audited and scored separately.
4. **Credibility contamination.** Shipping findings that read as whimsical trains maintainers to dismiss the tool. Mitigation: the lane's voice never appears in shipped output; hypothesis text is internal.
5. **Authority erosion.** "Irreverence" used to override a verified result. Mitigation: hard rule plus audit log, per O5.
6. **Prompt injection through framing.** An operator that tells the model to adopt an unexpected perspective can be steered by hostile repository content. Already an unresolved concern `[P]`; this lane widens the surface.
7. **Cost without portfolio evidence.** The lane triples hypothesis volume for an unknown gain. Acceptable only because the acceptance test is pre-registered and cheap to run.

---

## 6. Tests

- **False-premise canary.** Plant a premise that is demonstrably false (the function is not reachable unauthenticated, and this is provable) and count how many confident hypotheses the lane produces from it. The number that reach the shipped stream must be zero. This measures premise smuggling directly.
- **Composition canary.** Seed two findings that genuinely compose into an exploit, from different files, and measure whether O4 finds the chain. This is the operator with the strongest prior, so it is the one to validate first.
- **Inertness test.** Run the full lane on a module with no vulnerabilities. Hypothesis count should be high; shipped findings must be zero. A lane that ships nothing on clean code is working.
- **Duplication test.** Run the lane and the sober reviewers on the same artifacts and compute overlap. If duplication exceeds the pre-registered threshold, cut the lane.
- **Blind adjudication.** An adjudicator who does not know which lane produced a record judges each hypothesis. Knowledge of provenance changes judgments; withhold it.

---

## 7. What is and is not claimed

**Claimed.** The operators are mechanically specifiable. The output contract prevents promotion without an oracle. The metrics distinguish contribution from noise. The experiment is cheap and falsifiable.

**Not claimed.** That absurd humor improves detection. No source in this corpus tests incongruity, reframing or irreverence as review operators; a search for that literature was not performed for this run. The nearest documented practice is agentic decomposition and uncertainty-gated routing (D1 `[E]`), which is a different thing.

**The honest position.** This is a generator whose entire legitimacy is borrowed from a verifier it is not allowed to touch. If the verifier holds, the lane is a cheap way to widen the hypothesis space, and the incremental-recall number will say whether the widening was worth anything. If the verifier leaks, the lane is a fabrication engine with good branding, and the metric that catches it is premise error rate.
