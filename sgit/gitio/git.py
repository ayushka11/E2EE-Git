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

    def _run_bytes(self, *args: str, check: bool = True, env: dict[str, str] | None = None) -> bytes:
        full_env = os.environ.copy()
        full_env["GIT_TERMINAL_PROMPT"] = "0"
        if env:
            full_env.update(env)
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            env=full_env,
            check=False,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.decode('utf-8', errors='replace').strip()}")
        return proc.stdout

    @classmethod
    def clone(cls, url: str, dest: str | Path, identity: str, token: str | None = None) -> "Git":
        dest_path = Path(dest)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        proc = subprocess.run(
            ["git", "clone", "-b", "main", url, str(dest_path)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if proc.returncode != 0:
            proc = subprocess.run(
                ["git", "clone", url, str(dest_path)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
        if proc.returncode != 0:
            raise RuntimeError(f"git clone {url} failed: {proc.stderr.strip()}")
        git = cls(dest_path, identity, token)
        git._run("config", "user.name", identity)
        git._run("config", "user.email", f"{identity}@sgit.local")
        git._run("checkout", "-B", "main", "origin/main", check=False)
        return git

    def init(self, bare: bool = False) -> None:
        if bare:
            self._run("init", "--bare")
        else:
            self._run("init")
            self._run("config", "user.name", self.identity)
            self._run("config", "user.email", f"{self.identity}@sgit.local")

    def set_remote(self, url: str, name: str = "origin") -> None:
        remotes = [line.strip() for line in self._run("remote", check=False).splitlines()]
        if name in remotes:
            self._run("remote", "set-url", name, url)
        else:
            self._run("remote", "add", name, url)

    def current_head(self) -> str:
        return self._run("rev-parse", "HEAD", check=False).strip()

    def add_all(self) -> None:
        self._run("add", "-A")

    def commit(self, message: str) -> str:
        self._run("config", "user.name", self.identity)
        self._run("config", "user.email", f"{self.identity}@sgit.local")
        self._run("commit", "--allow-empty", "-m", message, check=False)
        out = self._run("rev-parse", "HEAD")
        return out.strip()

    def push(self, branch: str = "main", force: bool = False) -> None:
        self._run("branch", "-M", branch, check=False)
        cmd = ["push", "-u", "origin", branch]
        if force:
            cmd.append("--force")
        self._run(*cmd)

    def fetch(self) -> None:
        self._run("fetch", "origin", check=False)

    def rev_list(self, rng: str, first_parent: bool = True) -> list[str]:
        args = ["rev-list", "--reverse", rng]
        if first_parent:
            args.append("--first-parent")
        out = self._run(*args, check=False)
        return [line.strip() for line in out.splitlines() if line.strip()]

    def commit_info(self, c: str) -> dict[str, object]:
        out = self._run("show", "--no-patch", "--pretty=format:%H%x1F%P%x1F%B", c)
        parts = out.split("\x1f")
        h = parts[0]
        parent = parts[1] if len(parts) > 1 else ""
        msg = parts[2] if len(parts) > 2 else ""
        return {"id": h, "parents": parent.split() if parent else [], "message": msg}

    def read_tree(self, c: str) -> dict[str, bytes]:
        out = self._run("ls-tree", "-r", "-z", c, check=False)
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
            obj_hash = mode_and_hash[2]
            path = parts[1]
            blob = self._run_bytes("cat-file", "blob", obj_hash, check=False)
            files[path] = blob
        return files

    def write_tree(self, files: dict[str, bytes]) -> None:
        if self.path.exists():
            for child in self.path.iterdir():
                if child.name == ".git":
                    continue
                if child.is_dir():
                    for nested in sorted(child.rglob("*"), reverse=True):
                        if nested.is_file():
                            nested.unlink()
                        elif nested.is_dir():
                            nested.rmdir()
                    child.rmdir()
                else:
                    child.unlink()
        for path, content in files.items():
            file_path = self.path / path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(content)
        self._run("add", "-A")

    def estimate_push_bytes(self, old: str, new: str) -> int:
        rev_proc = subprocess.run(
            ["git", "-C", str(self.path), "rev-list", "--objects", f"{old}..{new}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if not rev_proc.stdout.strip():
            return 0
        pack_proc = subprocess.run(
            ["git", "-C", str(self.path), "pack-objects", "--thin", "--stdout"],
            input=rev_proc.stdout.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        if pack_proc.returncode == 0 and pack_proc.stdout:
            return len(pack_proc.stdout)
        return len(rev_proc.stdout.encode("utf-8"))
