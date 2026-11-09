# Security posture of assay

## Security invariant

No unauthorized change to a protected file causes repository code to execute before the change is
detected. `tools/hostile_matrix.py` attacks that statement rather than describing it: nine
mutations, each applied to a full copy of the tree, then the CI gate run in CI order. Detection is
judged by exit status; ordering is judged by a canary that only writes its marker if a protected
module is imported, with a control run that requires the marker to appear.

The matrix does not validate its own trust roots. The verifier digest and the anchor are supplied to
it from outside the copy, exactly as CI supplies them from repository variables. If those values
are compromised, every mutation passes.

## What this establishes

`python tools/integrity.py verify` reports by name any reviewed file that was added, removed or
modified, and requires the computed set digest to match the anchor below. That is drift detection
against a mutable baseline stored in this repository.

## What this does not establish

- **The verifier does not verify itself.** `tools/integrity.py` runs before it can be checked. CI
  pins its digest in a repository variable outside the checkout, so replacing the verifier also
  means editing CI settings. A cost, not a proof.
- **The anchor lives in the repository.** Whoever controls this repository can regenerate the lock
  and this file. Set `ASSAY_ANCHOR` and `ASSAY_VERIFIER_DIGEST` as repository variables and CI
  anchors both outside the checkout.
- **Nothing here is a signature.** No key material, no signed tags, no verified-commit requirement.
  Those are the real measures and they are not implemented.

## The anchor

```
    set digest: 8d0893304797cc69262a1faeb1b5301e3ac726e8c31948b520465ce2ff3faee9
    files:      75
```

`SECURITY.md` sits outside the covered set on purpose, so the anchor is not part of what it attests.
Verification parses both values and fails if either disagrees with the tree.

## Canonical repository

`github.com/1243353366/assay`, compared as a parsed host and path rather than a substring, because
`github.com/1243353366/assay-mirror` contains the canonical string and is a different repository.
HTTPS with credentials, `ssh://` and scp-style remotes are normalised before comparison.

## Checking a checkout you did not make

```
git remote get-url origin          # must parse to the canonical host and path
python tools/integrity.py all      # origin, drift, anchor
```
