# Security and provenance

## Canonical repository

    https://github.com/1243353366/assay

Anything else is a copy. A copy can be internally consistent, tests green and CI passing
while containing code nobody here reviewed. This file exists because that is the cheap
attack: clone, edit one module, keep the badge.

## Pinned digest

    set digest: 9223854630e0c9c904e67ce06a9a703d40d828bfd4307e3e439b4fc635dff072
    files:      69

`python tools/integrity.py digest` recomputes it from a checkout. If the number differs,
either the tree changed after review or you are not looking at this tree.

## Verify a checkout before you trust it

    git remote get-url origin          # must contain github.com/1243353366/assay
    python tools/integrity.py all      # origin, drift, added files, set digest
    python tools/integrity.py verify   # exits non-zero on any added, removed or modified file

CI runs `integrity all` before it executes anything from `harness/` or `tools/`, because
those files are run by path and a swapped file would otherwise execute with runner
privileges.

## What this does and does not establish

It detects **drift**: a file modified after review, removed, or added without review. The
added-file check is the one that matters for trojan drops, since a new module only has to be
importable to run.

It does not establish **authenticity**. The lock lives in the repository it protects, so
whoever controls the repository can regenerate it. The set digest is therefore pinned here
as well, which makes rewriting the lock a two-file change that a reviewer sees. That raises
the cost of a quiet edit; it does not make one impossible.

It cannot establish that a platform is trustworthy either. That is a different boundary, and
`harness/hardware/trust.py` answers it separately, with its own unverified and unknown
states. A clean software result here says nothing about firmware, provenance or DMA.

## Recommended for anyone consuming this

- Verify the digest against this file, not against the lock alone.
- Enable commit signature verification on any fork you actually run.
- Treat a green CI badge on an unfamiliar fork as a claim, not evidence.
- If the digest mismatches and you did not expect a change, treat the checkout as
  untrusted: do not run `tools/`, do not run CI on it, and diff against a known commit.

## Reporting

Open an issue on the canonical repository. Do not send exploit details to a fork's
maintainer list; verify you are talking to this repository first.
