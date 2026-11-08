"""Two-layer watermarking, because one layer is a suggestion.

Layer 1 (visible): a plausible account fragment, e.g. a trailing digit group that looks
like an internal asset id. Survives stripping invisible characters, which is the most
common cleanup an adversary applies.

Layer 2 (invisible): a zero-width sequence encoding the issuance fingerprint. Survives
copying, reformatting and partial quotation, because it travels inside the text rather
than beside it. It does not survive deliberate zero-width removal, and pretending
otherwise would be the kind of claim this repository exists to avoid.

Attribution returns every issuance it can find, in order, so a document assembled from
two leaks is reported as two leaks rather than the first one.
"""
from __future__ import annotations

import re

from . import Issuance

ALPHABET = {"0": "\u200b", "1": "\u200c"}
REVERSE = {v: k for k, v in ALPHABET.items()}

VISIBLE = re.compile(r"\[ref:[0-9a-f]{8}\]")
INVISIBLE = re.compile(r"[\u200b\u200c]{64}")


def visible_mark(issuance: Issuance) -> str:
    return f"[ref:{issuance.fingerprint('mark', 8)}]"


def invisible_mark(issuance: Issuance) -> str:
    """16 hex digits, one bit per zero-width character, 64 characters in total."""
    bits = bin(int(issuance.fingerprint("mark", 16), 16))[2:].zfill(64)
    return "".join(ALPHABET[b] for b in bits)


def apply(text: str, issuance: Issuance) -> str:
    """Insert both marks. The visible one goes where a reviewer would tolerate it."""
    body = text.rstrip("\n")
    return f"{body} {visible_mark(issuance)}{invisible_mark(issuance)}\n"


def apply_invisible(text: str, issuance: Issuance) -> str:
    """Mark without changing what a human (or a peer) reads.

    Command output carries only this layer: a `[ref:...]` inside `env` would be a gift to
    anyone deciding whether the box is real.
    """
    return text + invisible_mark(issuance)


def attribute(text: str) -> list[str]:
    """Every issuance id recoverable from this text, first position first.

    Text with both layers present yields the issuance once, not twice, because the
    visible and invisible marks are compared as a set.
    """
    found: list[tuple[int, str]] = []
    for match in VISIBLE.finditer(text):
        found.append((match.start(), match.group(0)[5:-1]))
    for match in INVISIBLE.finditer(text):
        bits = "".join(REVERSE[ch] for ch in match.group(0))
        for i in range(0, len(bits) - 63, 64):
            found.append((match.start(), f"{int(bits[i:i + 64], 2):016x}"[:8]))
    seen, ordered = set(), []
    for _, key in sorted(found):
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered
