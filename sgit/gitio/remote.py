from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal, Protocol


class Remote(Protocol):
    def create_repo(self, name: str) -> str: ...
    def delete_repo(self, name: str) -> None: ...
    def invite(self, name: str, login: str, perm: Literal["pull", "push"]) -> str: ...
    def accept(self, invitation_id: str, token: str) -> None: ...


class LocalBareRemote:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create_repo(self, name: str) -> str:
        path = self.root / name
        if path.exists():
            raise FileExistsError(name)
        subprocess.run(["git", "init", "--bare", "--initial-branch=main", str(path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return str(path)

    def delete_repo(self, name: str) -> None:
        path = self.root / name
        if path.exists():
            shutil.rmtree(path)

    def invite(self, name: str, login: str, perm: Literal["pull", "push"]) -> str:
        return f"{name}:{login}:{perm}"

    def accept(self, invitation_id: str, token: str) -> None:
        return None


class GitUrlRemote:
    """Remote wrapper for an existing Git remote repository URL (e.g. GitHub via SSH or HTTPS)."""

    def __init__(self, url: str):
        self.url = url

    def create_repo(self, name: str) -> str:
        return self.url

    def delete_repo(self, name: str) -> None:
        pass

    def invite(self, name: str, login: str, perm: Literal["pull", "push"]) -> str:
        return f"{name}:{login}:{perm}"

    def accept(self, invitation_id: str, token: str) -> None:
        return None


class GitHubRemote:
    def __init__(self, token: str):
        self.token = token

    def create_repo(self, name: str) -> str:
        raise NotImplementedError("GitHub remote requires the REST API; use GitUrlRemote for existing SSH/HTTPS repos.")

    def delete_repo(self, name: str) -> None:
        raise NotImplementedError("GitHub remote requires the REST API; use GitUrlRemote for existing SSH/HTTPS repos.")

    def invite(self, name: str, login: str, perm: Literal["pull", "push"]) -> str:
        raise NotImplementedError("GitHub remote requires the REST API; use GitUrlRemote for existing SSH/HTTPS repos.")

    def accept(self, invitation_id: str, token: str) -> None:
        raise NotImplementedError("GitHub remote requires the REST API; use GitUrlRemote for existing SSH/HTTPS repos.")
