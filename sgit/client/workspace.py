from __future__ import annotations

import json
from pathlib import Path


class WorkspaceClient:
    """Small state holder for the local plaintext and ciphertext repositories."""

    def __init__(self, repo_dir: str | Path, rid: str, owner: str):
        self.root = Path(repo_dir)
        self.rid = rid
        self.owner = owner
        self.state_path = self.root / "state.json"
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "plain").mkdir(exist_ok=True)
        (self.root / "ct").mkdir(exist_ok=True)

    def save_state(self, last_ct_commit: str, last_digest: bytes, ct_to_plain: dict[str, str]):
        payload = {
            "rid": self.rid,
            "owner": self.owner,
            "last_ct_commit": last_ct_commit,
            "last_digest": last_digest.hex(),
            "ct_to_plain": ct_to_plain,
        }
        self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    def load_state(self) -> dict:
        if not self.state_path.exists():
            return {}
        return json.loads(self.state_path.read_text(encoding="utf-8"))
