"""Simple protocol wrappers for registration and authentication."""

from __future__ import annotations

from pathlib import Path

from sgit.crypto.keystore import Keystore
from sgit.service.service import SgitService


def register(service: SgitService, uid: str, github_login: str, passphrase: str, keystore_path: str | Path) -> bytes:
    keystore = Keystore(str(keystore_path), passphrase)
    pk_e, sk_e = keystore.public_ephemeral, keystore.private_ephemeral
    pk_s, sk_s = keystore.public_signing, keystore.private_signing
    return service.register(uid, pk_e, pk_s, github_login)


def authenticate(service: SgitService, uid: str, cred: bytes) -> str:
    return service.authenticate(uid, cred)
