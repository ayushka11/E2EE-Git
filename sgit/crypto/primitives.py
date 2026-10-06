import base64
import hashlib
import hmac
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES


def H(label: bytes, *parts: bytes) -> bytes:
    """Hash with a fixed domain label and length-prefixing for each part."""
    h = hashlib.sha256()
    h.update(label)
    for part in parts:
        h.update(len(part).to_bytes(8, "big", signed=False))
        h.update(part)
    return h.digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if salt is None:
        salt = b""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm += previous
        counter += 1
    return okm[:length]


def kdf(mk: bytes, rid: str) -> bytes:
    info = b"sgit/v1/repo-key" + rid.encode("utf-8")
    return hkdf_sha256(mk, b"sgitline", info, 32)


def se_keygen() -> bytes:
    return os.urandom(32)


def se_enc(k: bytes, m: bytes) -> bytes:
    if len(k) != 32:
        raise ValueError("SE key must be 32 bytes")
    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    return iv + cipher.encrypt(m)


def se_dec(k: bytes, c: bytes) -> bytes:
    if len(c) < 16:
        raise ValueError("Ciphertext too short")
    iv = c[:16]
    cipher = AES.new(k, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    return cipher.decrypt(c[16:])


def ds_keygen() -> tuple[bytes, bytes]:
    sk = ed25519.Ed25519PrivateKey.generate()
    private_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def ds_sign(sk: bytes, msg: bytes) -> bytes:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(sk)
    return key.sign(msg)


def ds_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(pk)
        key.verify(sig, msg)
        return True
    except Exception:
        return False


def pke_keygen() -> tuple[bytes, bytes]:
    sk = x25519.X25519PrivateKey.generate()
    private_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def pke_enc(pk: bytes, m: bytes) -> bytes:
    receiver = x25519.X25519PublicKey.from_public_bytes(pk)
    eph = x25519.X25519PrivateKey.generate()
    shared = eph.exchange(receiver)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"sgitline-pke-v1",
    ).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, m, None)
    return eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) + nonce + ct


def pke_dec(sk: bytes, c: bytes) -> bytes:
    if len(c) < 32 + 12 + 16:
        raise ValueError("Ciphertext too short")
    eph_pub = c[:32]
    nonce = c[32:32 + 12]
    ct = c[32 + 12:]
    receiver = x25519.X25519PrivateKey.from_private_bytes(sk)
    peer = x25519.X25519PublicKey.from_public_bytes(eph_pub)
    shared = receiver.exchange(peer)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"sgitline-pke-v1",
    ).derive(shared)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:  # pragma: no cover - explicit failure path
        raise ValueError("decryption failed") from exc
