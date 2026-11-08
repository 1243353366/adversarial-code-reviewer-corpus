"""Synthetic command output. Whitelisted, deterministic, and never executed.

The naive handler this replaces ran the peer's string through a shell with `subprocess`;
the hardened one recognizes a narrow command grammar and answers from data it already
holds. Anything unrecognized gets a plausible failure, because a honeypot that returns
"unknown command" to everything is a honeypot with a signature.

Two hazards are handled explicitly. `env` must not leak the listener's environment, since
that would hand over real cloud credentials, proxies and usernames. And every response is
built from the fake vault, so a stolen transcript attributes back to an issuance.
"""
from __future__ import annotations

from . import Issuance
from . import watermark
from .credentials import CredentialRegistry
from .vault import EscapedRoot, FakeTree

WHITELIST = ("whoami", "hostname", "id", "uname", "pwd", "ls", "cat", "env", "ps", "history")


class SimulatedShell:
    def __init__(self, issuance: Issuance, registry: CredentialRegistry, tree: FakeTree) -> None:
        self.issuance = issuance
        self.registry = registry
        self.tree = tree
        self.history: list[str] = []

    def _wrap(self, stdout: str, code: int = 0) -> dict:
        return {
            "stdout": watermark.apply_invisible(stdout, self.issuance),
            "stderr": "",
            "exit": code,
            "issuance_id": self.issuance.issuance_id,
        }

    def run(self, line: str) -> dict:
        self.history.append(line)
        argv = line.strip().split()
        if not argv:
            return {"stdout": "", "stderr": "", "exit": 0, "issuance_id": self.issuance.issuance_id}
        cmd, args = argv[0], argv[1:]
        handler = getattr(self, f"_cmd_{cmd}", None)
        if cmd not in WHITELIST or handler is None:
            return {
                "stdout": "",
                "stderr": f"{cmd}: command not found\n",
                "exit": 127,
                "issuance_id": self.issuance.issuance_id,
            }
        try:
            return handler(args)
        except EscapedRoot:
            return {"stdout": "", "stderr": f"{cmd}: No such file or directory\n", "exit": 2,
                    "issuance_id": self.issuance.issuance_id}

    # --- commands -----------------------------------------------------------
    def _cmd_whoami(self, args: list[str]) -> dict:
        return self._wrap("svc-deploy\n")

    def _cmd_hostname(self, args: list[str]) -> dict:
        return self._wrap("build-runner-07\n")

    def _cmd_id(self, args: list[str]) -> dict:
        return self._wrap("uid=1002(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy)\n")

    def _cmd_uname(self, args: list[str]) -> dict:
        return self._wrap("Linux build-runner-07 6.1.0-18-amd64 #1 SMP x86_64 GNU/Linux\n")

    def _cmd_pwd(self, args: list[str]) -> dict:
        return self._wrap("/srv/app\n")

    def _cmd_ls(self, args: list[str]) -> dict:
        target = args[-1] if args else "/srv/app"
        try:
            names = self.tree.listing(target)
        except EscapedRoot:
            raise
        return self._wrap("\n".join(names) + "\n" if names else "")

    def _cmd_cat(self, args: list[str]) -> dict:
        if not args:
            return {"stdout": "", "stderr": "cat: missing operand\n", "exit": 1,
                    "issuance_id": self.issuance.issuance_id}
        return self._wrap(self.tree.read(args[0], purpose="cat"))

    def _cmd_env(self, args: list[str]) -> dict:
        """Synthetic only. The listener's own environment must never appear here."""
        lines = [
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "HOME=/home/svc-deploy",
            "SHELL=/bin/bash",
            "AWS_ACCESS_KEY_ID=" + self.registry.aws_like(self.issuance),
            "AWS_SECRET_ACCESS_KEY=" + self.registry.secret_key(self.issuance),
            "DB_PASSWORD=" + self.registry.db_password(self.issuance),
            "DEPLOY_TOKEN=" + self.issuance.fingerprint("deploy_token", 24),
        ]
        return self._wrap("\n".join(lines) + "\n")

    def _cmd_ps(self, args: list[str]) -> dict:
        return self._wrap(
            "  PID TTY          TIME CMD\n"
            "    1 ?        00:00:02 systemd\n"
            "  412 ?        00:00:11 nginx\n"
            "  733 ?        00:00:04 python3 -m app.worker\n"
        )

    def _cmd_history(self, args: list[str]) -> dict:
        return self._wrap("\n".join(self.history) + "\n")
