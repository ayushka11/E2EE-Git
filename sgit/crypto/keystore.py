from __future__ import annotations

import hashlib
import json
import os

from Crypto.Cipher import AES

from sgit.crypto.primitives import ds_keygen, pke_keygen


class Keystore:
    """A tiny passphrase-protected keystore for local keys."""

    def __init__(self, path: str, passphrase: str):
        self.path = path
        self.passphrase = passphrase.encode("utf-8")
        self.private_ephemeral = b""
        self.public_ephemeral = b""
        self.private_signing = b""
        self.public_signing = b""

    def _derive_key(self, salt: bytes) -> bytes:
        return hashlib.scrypt(self.passphrase, salt=salt, n=2**15, r=8, p=1, dklen=32)

    def load(self) -> None:
        if not os.path.exists(self.path):
            self._generate_new()
            return
        with open(self.path, "rb") as handle:
            content = handle.read()
        salt = content[:16]
        nonce = content[16:28]
        tag = content[28:44]
        ciphertext = content[44:]
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise ValueError("wrong passphrase or corrupted keystore") from exc
        data = json.loads(plaintext.decode("utf-8"))
        self.private_ephemeral = bytes.fromhex(data["sk_e"])
        self.public_ephemeral = bytes.fromhex(data["pk_e"])
        self.private_signing = bytes.fromhex(data["sk_s"])
        self.public_signing = bytes.fromhex(data["pk_s"])

    def save(self) -> None:
        data = {
            "pk_e": self.public_ephemeral.hex(),
            "sk_e": self.private_ephemeral.hex(),
            "pk_s": self.public_signing.hex(),
            "sk_s": self.private_signing.hex(),
        }
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = json.dumps(data, sort_keys=True).encode("utf-8")
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        with open(self.path, "wb") as handle:
            handle.write(salt + nonce + tag + ciphertext)

    def _generate_new(self) -> None:
        sk_e, pk_e = pke_keygen()
        sk_s, pk_s = ds_keygen()
        self.private_ephemeral = sk_e
        self.public_ephemeral = pk_e
        self.private_signing = sk_s
        self.public_signing = pk_s
        self.save()
