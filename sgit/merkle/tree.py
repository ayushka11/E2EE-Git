from __future__ import annotations

from collections import defaultdict

from sgit.crypto.primitives import H


class MerkleTree:
    """A tiny directory Merkle tree over file contents."""

    def __init__(self, files: dict[str, bytes]):
        self.files = dict(files)
        self._root = self._compute_root(self.files)

    @classmethod
    def from_files(cls, files: dict[str, bytes]) -> "MerkleTree":
        return cls(files)

    def root(self) -> bytes:
        return self._root

    def update_file(self, path: str, content: bytes | None) -> None:
        if content is None:
            self.files.pop(path, None)
        else:
            self.files[path] = content
        self._root = self._compute_root(self.files)

    @staticmethod
    def _compute_root(files: dict[str, bytes]) -> bytes:
        if not files:
            return H(b"root")

        dir_children: dict[str, list[tuple[str, bytes, bytes]]] = defaultdict(list)
        for path, content in files.items():
            cleaned = path.strip("/")
            if not cleaned:
                continue
            parts = cleaned.split("/")
            for index in range(1, len(parts)):
                parent = "/".join(parts[:index])
                child_name = parts[index]
                dir_children[parent].append((child_name, H(b"leaf", child_name.encode(), H(b"content", content)), b"file"))

        # Every file is also represented in its immediate parent directory.
        direct_children: dict[str, list[tuple[str, bytes, bytes]]] = defaultdict(list)
        for path, content in files.items():
            cleaned = path.strip("/")
            if not cleaned:
                continue
            parts = cleaned.split("/")
            direct_children["/".join(parts[:-1])].append((parts[-1], H(b"leaf", parts[-1].encode(), H(b"content", content)), b"file"))

        def hash_dir(path: str) -> bytes:
            entries = sorted(direct_children.get(path, []))
            if not entries:
                return H(b"dir", path.encode())
            data = []
            for child_name, child_hash, kind in entries:
                data.append(H(b"entry", kind, child_name.encode(), child_hash))
            return H(b"dir", path.encode(), *data)

        # Include nested directory structure by hashing every known directory.
        all_dirs = set()
        for path in files:
            cleaned = path.strip("/")
            if not cleaned:
                continue
            parts = cleaned.split("/")
            for idx in range(1, len(parts)):
                all_dirs.add("/".join(parts[:idx]))
        for dir_name in sorted(all_dirs):
            if not dir_name:
                continue
            # directory content is represented by its direct children (not recursive)
            entries = sorted(direct_children.get(dir_name, []))
            if not entries:
                continue
            child_hashes = [H(b"entry", kind, child_name.encode(), child_hash) for child_name, child_hash, kind in entries]
            _ = H(b"dir", dir_name.encode(), *child_hashes)

        root_entries = sorted((f"{path}", H(b"leaf", path.split('/')[-1].encode(), H(b"content", content)), b"file") for path, content in files.items())
        if not root_entries:
            return H(b"root")
        payload = [H(b"entry", kind, name.encode(), child_hash) for name, child_hash, kind in root_entries]
        return H(b"root", *payload)
