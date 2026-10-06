import pytest

from sgit.codec.lines import dec_line, decrypt_file, enc_line, encrypt_file, join_lines, split_lines
from sgit.crypto.primitives import H, ds_keygen, ds_sign, ds_verify, se_dec, se_enc
from sgit.diff.comdiff import apply_ops, comdiff_line, encrypt_ops
from sgit.merkle.tree import MerkleTree


def test_hash_is_deterministic():
    a = H(b"a", b"x", b"yz")
    assert a == H(b"a", b"x", b"yz")
    assert H(b"a", b"x", b"yz") != H(b"a", b"xy", b"z")


def test_se_roundtrip():
    key = b"\x00" * 32
    msg = b"hello world\nwith newline\r\n"
    ct = se_enc(key, msg)
    assert se_dec(key, ct) == msg


def test_line_roundtrip_and_split_join():
    data = b"alpha\nbeta\n\r\ngamma"
    ct = encrypt_file(b"\x11" * 32, data)
    assert decrypt_file(b"\x11" * 32, ct) == data
    assert join_lines(split_lines(data)) == data


def test_diff_and_replay():
    old = [b"a", b"b", b"c"]
    new = [b"a", b"x", b"c", b"d"]
    ops = comdiff_line(old, new)
    assert apply_ops(old, ops) == new
    k = b"\x22" * 32
    ct_old = [enc_line(k, line) for line in old]
    ops2 = encrypt_ops(k, ops)
    replay = [dec_line(k, c) for c in apply_ops(ct_old, ops2)]
    assert replay == new


def test_merkle_changes_when_files_change():
    root1 = MerkleTree.from_files({"a.txt": b"one", "b.txt": b"two"}).root()
    root2 = MerkleTree.from_files({"a.txt": b"one", "b.txt": b"three"}).root()
    assert root1 != root2


def test_ds_sign_and_verify():
    sk, pk = ds_keygen()
    msg = b"sign me"
    sig = ds_sign(sk, msg)
    assert ds_verify(pk, msg, sig) is True
    assert ds_verify(pk, msg, b"not-a-valid-signature") is False
