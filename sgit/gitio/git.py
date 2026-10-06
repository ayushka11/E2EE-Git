from __future__ import annotations

import os
import subprocess
from pathlib import Path


class Git:
    def __init__(self, path: str | Path, identity: str, token: str | None = None):
        self.path = Path(path)
        self.identity = identity
        self.token = token

    def _run(self, *args: str, check: bool = True, env: dict[str, str] | None = None) -> str:
        full_env = os.environ.copy()
        full_env["GIT_TERMINAL_PROMPT"] = "0"
        if env:
            full_env.update(env)
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            env=full_env,
            check=False,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout

    def init(self, bare: bool = False) -> None:
        if bare:
            self._run("init", "--bare")
        else:
            self._run("init")

    def add_all(self) -> None:
        self._run("add", ".")

    def commit(self, message: str) -> str:
        self._run("config", "user.name", self.identity)
        self._run("config", "user.email", f"{self.identity}@sgit.local")
        self._run("commit", "-m", message, check=False)
        out = self._run("rev-parse", "HEAD")
        return out.strip()

    def push(self, branch: str = "main", force: bool = False) -> None:
        cmd = ["push", "origin", f"{branch}"]
        if force:
            cmd.append("--force")
        self._run(*cmd)

    def fetch(self) -> None:
        self._run("fetch", "origin")

    def rev_list(self, rng: str, first_parent: bool = True) -> list[str]:
        args = ["rev-list", "--reverse", rng]
        if first_parent:
            args.append("--first-parent")
        out = self._run(*args)
        return [line.strip() for line in out.splitlines() if line.strip()]

    def commit_info(self, c: str) -> dict[str, object]:
        out = self._run("show", "--no-patch", "--pretty=format:%H%x1F%P%x1F%s", c)
        h, parent, msg = out.split("\x1f")
        return {"id": h, "parents": parent.split() if parent else [], "message": msg}

    def read_tree(self, c: str) -> dict[str, bytes]:
        out = self._run("ls-tree", "-r", "-z", c)
        files: dict[str, bytes] = {}
        for entry in out.split("\0"):
            if not entry:
                continue
            parts = entry.split("\t")
            if len(parts) != 2:
                continue
            mode_and_hash = parts[0].split()
            if len(mode_and_hash) < 3:
                continue
            path = parts[1]
            blob = self._run("cat-file", "-p", f"{mode_and_hash[2]}^{mode_and_hash[1]}", check=False)
            files[path] = blob.encode("utf-8", errors="surrogateescape")
        return files

    def write_tree(self, files: dict[str, bytes]) -> None:
        if self.path.exists():
            for child in self.path.iterdir():
                if child.name == ".git":
                    continue
                if child.is_dir():
                    for nested in child.rglob("*"):
                        if nested.is_file():
                            nested.unlink()
                    child.rmdir()
                else:
                    child.unlink()
        for path, content in files.items():
            file_path = self.path / path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(content)
        self._run("add", ".")
        self._run("commit", "-m", "write_tree", check=False)

    def estimate_push_bytes(self, old: str, new: str) -> int:
        # Very small helper for learning use; count git pack size between revisions.
        out = self._run("rev-list", "--objects", f"{old}..{new}")
        return len(out.encode("utf-8"))
