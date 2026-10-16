from __future__ import annotations

import json
from pathlib import Path


class WorkspaceClient:
    """State holder for the local plaintext and ciphertext repositories."""

    def __init__(self, repo_dir: str | Path, rid: str = "", owner: str = ""):
        self.root = Path(repo_dir).resolve()
        self.state_path = self.root / "state.json"
        self.plain_dir = self.root / "plain"
        self.ct_dir = self.root / "ct"
        self.root.mkdir(parents=True, exist_ok=True)
        self.plain_dir.mkdir(exist_ok=True)
        self.ct_dir.mkdir(exist_ok=True)
        state = self.load_state()
        self.rid = rid or state.get("rid", "")
        self.owner = owner or state.get("owner", "")
        self.remote_url = state.get("remote_url", "")

    def save_state(
        self,
        last_ct_commit: str,
        last_digest: bytes,
        ct_to_plain: dict[str, str] | None = None,
        remote_url: str | None = None,
        rid: str | None = None,
        owner: str | None = None,
    ) -> None:
        if rid:
            self.rid = rid
        if owner:
            self.owner = owner
        if remote_url is not None:
            self.remote_url = remote_url
        payload = {
            "rid": self.rid,
            "owner": self.owner,
            "remote_url": self.remote_url,
            "last_ct_commit": last_ct_commit,
            "last_digest": last_digest.hex(),
            "ct_to_plain": ct_to_plain or {},
        }
        self.state_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def load_state(self) -> dict:
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def read_plain_files(self) -> dict[str, bytes]:
        return self._read_dir_files(self.plain_dir)

    def read_ct_files(self) -> dict[str, bytes]:
        return self._read_dir_files(self.ct_dir)

    def _read_dir_files(self, base_dir: Path) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        if not base_dir.exists():
            return files
        for p in base_dir.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(base_dir).as_posix()
            if rel == ".git" or rel.startswith(".git/"):
                continue
            files[rel] = p.read_bytes()
        return files

    def write_plain_files(self, files: dict[str, bytes]) -> None:
        self._write_dir_files(self.plain_dir, files)

    def write_ct_files(self, files: dict[str, bytes]) -> None:
        self._write_dir_files(self.ct_dir, files)

    def _write_dir_files(self, base_dir: Path, files: dict[str, bytes]) -> None:
        base_dir.mkdir(parents=True, exist_ok=True)
        for child in list(base_dir.iterdir()):
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
        for rel_path, content in files.items():
            file_path = base_dir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(content)

