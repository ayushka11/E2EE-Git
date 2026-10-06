from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path


_UID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


@dataclass
class RepoRecord:
    rid: str
    owner_uid: str
    gh_name: str


class SgitService:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.db_path)
        self.connection.execute("CREATE TABLE IF NOT EXISTS users (uid TEXT PRIMARY KEY, pk_e BLOB, pk_s BLOB, github_login TEXT, cred_hash TEXT)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, uid TEXT, expires REAL)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS repos (rid TEXT PRIMARY KEY, owner_uid TEXT, gh_name TEXT)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS access (rid TEXT, uid TEXT, mode TEXT)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS pending (rid TEXT, uid_re TEXT, oob TEXT, acs TEXT)")
        self.connection.commit()

    def register(self, uid: str, pk_e: bytes, pk_s: bytes, github_login: str) -> bytes:
        if not _UID_RE.fullmatch(uid):
            raise ValueError("invalid uid")
        if self.connection.execute("SELECT 1 FROM users WHERE uid = ?", (uid,)).fetchone():
            raise ValueError("duplicate uid")
        cred = os.urandom(32)
        self.connection.execute(
            "INSERT INTO users (uid, pk_e, pk_s, github_login, cred_hash) VALUES (?, ?, ?, ?, ?)",
            (uid, pk_e, pk_s, github_login, hashlib.sha256(cred).hexdigest()),
        )
        self.connection.commit()
        return cred

    def authenticate(self, uid: str, cred: bytes) -> str:
        row = self.connection.execute("SELECT cred_hash FROM users WHERE uid = ?", (uid,)).fetchone()
        if row is None:
            raise ValueError("unknown user")
        expected = row[0]
        if not hmac.compare_digest(hashlib.sha256(cred).hexdigest(), expected):
            raise ValueError("bad credential")
        sid = uuid.uuid4().hex
        self.connection.execute("INSERT INTO sessions (sid, uid, expires) VALUES (?, ?, ?)", (sid, uid, 1_000_000_000_000))
        self.connection.commit()
        return sid

    def get_keys(self, uid: str) -> tuple[bytes, bytes]:
        row = self.connection.execute("SELECT pk_e, pk_s FROM users WHERE uid = ?", (uid,)).fetchone()
        if row is None:
            raise ValueError("unknown user")
        return row[0], row[1]

    def create_repo_record(self, sid: str, rid: str, gh_name: str) -> None:
        owner_uid = self._uid_for_session(sid)
        if self.connection.execute("SELECT 1 FROM repos WHERE rid = ?", (rid,)).fetchone():
            raise ValueError("rid already exists")
        self.connection.execute("INSERT INTO repos (rid, owner_uid, gh_name) VALUES (?, ?, ?)", (rid, owner_uid, gh_name))
        self.connection.commit()

    def get_repo(self, sid: str, rid: str) -> RepoRecord:
        owner_uid = self._uid_for_session(sid)
        row = self.connection.execute("SELECT owner_uid, gh_name FROM repos WHERE rid = ?", (rid,)).fetchone()
        if row is None:
            raise ValueError("unknown repo")
        if row[0] != owner_uid:
            raise ValueError("access denied")
        return RepoRecord(rid=rid, owner_uid=row[0], gh_name=row[1])

    def _uid_for_session(self, sid: str) -> str:
        row = self.connection.execute("SELECT uid FROM sessions WHERE sid = ?", (sid,)).fetchone()
        if row is None:
            raise ValueError("unknown session")
        return row[0]

    def share_request(self, sid: str, rid: str, uid_re: str, acs: str) -> str:
        owner_uid = self._uid_for_session(sid)
        oob = uuid.uuid4().hex
        self.connection.execute("INSERT INTO pending (rid, uid_re, oob, acs) VALUES (?, ?, ?, ?)", (rid, uid_re, oob, acs))
        self.connection.commit()
        return oob

    def share_accept(self, sid: str, rid: str, oob: str) -> None:
        uid = self._uid_for_session(sid)
        row = self.connection.execute("SELECT rid, uid_re FROM pending WHERE rid = ? AND oob = ?", (rid, oob)).fetchone()
        if row is None:
            raise ValueError("bad oob")
        if row[1] != uid:
            raise ValueError("wrong user")
        self.connection.execute("INSERT INTO access (rid, uid, mode) VALUES (?, ?, 'read')", (rid, uid))
        self.connection.execute("DELETE FROM pending WHERE rid = ? AND oob = ?", (rid, oob))
        self.connection.commit()
