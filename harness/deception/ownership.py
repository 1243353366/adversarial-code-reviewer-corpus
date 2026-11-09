"""One ownership model, agreed on by the filesystem, the canary, and the hooks.

Before this module, four components each kept their own idea of who owned what: the filesystem had
an environment, the canary had a token and paths, the registry had a token index, and the runtime
had a session id. Each was individually consistent and collectively wrong, which is why a read in
one session could fire another session's alarm and why nothing noticed.

This module does not add a fifth opinion. It audits the four against each other and returns the
disagreements. A disagreement is a failure, not a warning: a detector that attributes an event to
the wrong session is worse than no detector, because it produces evidence that reads as true.
"""

from __future__ import annotations

PLANT_MARKERS = ("canary", "predictable")


def _registry_of(mirror):
    return getattr(mirror, "canaries", None)


def audit(mirror) -> list[str]:
    """Return every disagreement about ownership. Empty means the four agree."""
    problems: list[str] = []
    registry = _registry_of(mirror)
    if registry is None:
        return ["mirror has no canary registry, so ownership is unestablished"]

    sessions = getattr(mirror, "sessions", {})
    by_session = getattr(registry, "by_session", {})

    ids = [s.session_id for s in sessions.values()]
    if len(ids) != len(set(ids)):
        problems.append("two routing entries share one session identity")

    for session in sessions.values():
        session_id = session.session_id
        canary = by_session.get(session_id)
        if canary is None:
            problems.append(f"{session_id}: owns a filesystem but no canary")
            continue
        if canary.session_id != session_id:
            problems.append(f"{session_id}: canary belongs to {canary.session_id}")

        env = getattr(session, "env", None)
        files = getattr(env, "files", {}) if env is not None else {}
        for path in canary.planted_at:
            body = files.get(path, "")
            if path not in files:
                problems.append(f"{session_id}: planted {path} is absent from its filesystem")
            elif canary.token not in body:
                problems.append(f"{session_id}: {path} does not contain its own token")

        for other_id in set(by_session) - {session_id}:
            if other_id == session_id:
                continue
            other = by_session.get(other_id)
            if other is None:
                continue
            for path in canary.planted_at:
                if other.token and other.token in files.get(path, ""):
                    problems.append(f"{session_id}: {path} contains {other_id}'s token")

    owners: dict[str, str] = {}
    for session_id, canary in by_session.items():
        if canary.token in owners and owners[canary.token] != session_id:
            problems.append(f"token shared by {owners[canary.token]} and {session_id}")
        owners[canary.token] = session_id
        indexed = getattr(registry, "by_token", {}).get(canary.token)
        if indexed is not None and indexed.session_id != session_id:
            problems.append(f"token index points {canary.token[-6:]} at {indexed.session_id}")

    for session_id, canary in by_session.items():
        for touch in canary.touches:
            seen = touch.get("seen_in")
            if seen in (None, session_id):
                continue
            if touch.get("where", "").startswith("file_read"):
                problems.append(
                    f"{session_id}: a file read by {seen} was attributed as its own")
    return problems


def owner_of(mirror, session_id: str) -> str | None:
    canary = getattr(mirror, "canaries", None)
    if canary is None:
        return None
    owner = canary.by_session.get(session_id)
    return owner.token if owner else None


def main(argv=None) -> int:
    from harness.deception import mirror as mx_mod

    mirror = mx_mod.Mirror(variation=False)
    a = mirror.connect("198.51.100.41:41412")
    b = mirror.connect("198.51.100.42:41412")
    a.send("cat /var/www/app/.env\n")
    b.send("cat /home/deploy/.aws/credentials\n")
    b.send("export KEY=" + mirror.canaries.by_session[a.session_id].token + "\n")

    problems = audit(mirror)
    tokens = {sid: c.token[-6:] for sid, c in mirror.canaries.by_session.items()}
    print(f"sessions {len(mirror.sessions)}, distinct tokens {len(set(tokens.values()))}")
    print(f"ownership audit: {'clean' if not problems else str(len(problems)) + ' problem(s)'}")
    for problem in problems:
        print("  " + problem)
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
