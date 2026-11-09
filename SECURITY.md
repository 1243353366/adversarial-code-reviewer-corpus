# Security posture of assay

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
    set digest: 877974401e35b9292ab83d21e7be3aae3dfe2aec45c9554192839e9a2ff675df
    files:      69
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
