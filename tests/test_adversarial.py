from pathlib import Path

import pytest

from sgit.client import protocols
from sgit.client.workspace import WorkspaceClient
from sgit.crypto.keystore import Keystore
from sgit.crypto.primitives import ds_sign
from sgit.gitio.git import Git
from sgit.gitio.remote import LocalBareRemote
from sgit.merkle.tree import MerkleTree
from sgit.model.version import Tag, tag_to_message, version_digest
from sgit.service.service import SgitService


@pytest.fixture
def env(tmp_path: Path):
    db_path = tmp_path / "service.db"
    service = SgitService(db_path)
    remote = LocalBareRemote(tmp_path / "remotes")
    return service, remote, tmp_path


def test_tampered_ciphertext_fails_pull(env):
    """An honest-but-curious or malicious host flips a bit in a ciphertext file."""
    service, remote, tmp_path = env
    ks_path = tmp_path / "owner.dat"
    cred = protocols.register(service, "owner", "owner-gh", "pw", ks_path)
    sid = protocols.authenticate(service, "owner", cred)
    keystore = Keystore(str(ks_path), "pw")

    remote_url = remote.create_repo("tamper1.git")
    repo_dir = tmp_path / "owner_repo"
    rid = protocols.init_repo(service, sid, keystore, repo_dir, remote_url, {"file.txt": b"Authentic line\n"})

    # Clone to a second client (reader)
    reader_ks = tmp_path / "reader.dat"
    reader_cred = protocols.register(service, "reader", "reader-gh", "pw", reader_ks)
    reader_sid = protocols.authenticate(service, "reader", reader_cred)
    reader_keystore = Keystore(str(reader_ks), "pw")
    oob = protocols.share_repo(service, sid, keystore, repo_dir, "reader", write=False)

    reader_repo = tmp_path / "reader_repo"
    protocols.accept_share(service, reader_sid, reader_keystore, reader_repo, rid, oob, remote_url)
    reader_ws = WorkspaceClient(reader_repo)
    original_plain = reader_ws.read_plain_files()

    # Owner updates the repo
    (WorkspaceClient(repo_dir).plain_dir / "file.txt").write_bytes(b"Authentic line\nSecond authentic line\n")
    protocols.update_repo(service, sid, keystore, repo_dir, "Update 2")

    # Attacker tampers directly with the bare remote!
    # They clone the bare remote, modify the file, create a new commit with the same tag message or edit it
    attacker_clone_dir = tmp_path / "attacker_clone"
    attacker_git = Git.clone(remote_url, attacker_clone_dir, "attacker")
    tampered_files = attacker_git.read_tree("HEAD")
    # Flip bytes in ciphertext
    ct = bytearray(tampered_files["file.txt"])
    ct[5] = ct[5] ^ 0x01
    tampered_files["file.txt"] = bytes(ct)
    attacker_git.write_tree(tampered_files)
    # Commit with identical tag message
    info = attacker_git.commit_info("HEAD~1")
    attacker_git.commit(str(info["message"]))
    attacker_git.push("main", force=True)

    # Reader pulls: MUST fail due to signature or Merkle root mismatch
    with pytest.raises(Exception):
        protocols.pull_repo(service, reader_sid, reader_keystore, reader_repo)

    # Reader local plaintext must be completely unchanged (fail-closed guarantee)
    assert reader_ws.read_plain_files() == original_plain


def test_unauthorized_writer_rejected_by_pull(env):
    """A reader signs a valid version with their own key and pushes; pull rejects it."""
    service, remote, tmp_path = env
    ks_path = tmp_path / "owner.dat"
    cred = protocols.register(service, "owner", "owner-gh", "pw", ks_path)
    sid = protocols.authenticate(service, "owner", cred)
    keystore = Keystore(str(ks_path), "pw")

    remote_url = remote.create_repo("unauth.git")
    repo_dir = tmp_path / "owner_repo"
    rid = protocols.init_repo(service, sid, keystore, repo_dir, remote_url, {"secret.txt": b"Secret\n"})

    # Register reader
    reader_ks = tmp_path / "reader.dat"
    reader_cred = protocols.register(service, "reader", "reader-gh", "pw", reader_ks)
    reader_sid = protocols.authenticate(service, "reader", reader_cred)
    reader_keystore = Keystore(str(reader_ks), "pw")

    oob = protocols.share_repo(service, sid, keystore, repo_dir, "reader", write=False)

    reader_repo = tmp_path / "reader_repo"
    protocols.accept_share(service, reader_sid, reader_keystore, reader_repo, rid, oob, remote_url)
    reader_ws = WorkspaceClient(reader_repo)

    # Reader bypasses the CLI and uses raw Git to craft a commit signed with reader's key
    reader_ct_git = Git(reader_ws.ct_dir, "reader")
    current_files = reader_ct_git.read_tree("HEAD")
    current_files["injected.txt"] = b"c29tZV9jaXBoZXJ0ZXh0Cg==\n"
    reader_ct_git.write_tree(current_files)

    rh = MerkleTree.from_files(current_files).root()
    last_digest = bytes.fromhex(reader_ws.load_state()["last_digest"])
    digest = version_digest(rid, "reader", rh, last_digest)
    sig = ds_sign(reader_keystore.private_signing, digest)
    tag_msg = tag_to_message(Tag("reader", last_digest, sig))

    reader_ct_git.commit(tag_msg)
    reader_ct_git.push("main", force=True)

    # Owner pulls: MUST reject the commit because reader is not in W
    owner_ws = WorkspaceClient(repo_dir)
    owner_plain_before = owner_ws.read_plain_files()
    with pytest.raises(ValueError, match="not authorized to write"):
        protocols.pull_repo(service, sid, keystore, repo_dir)

    # Owner's plaintext is intact
    assert owner_ws.read_plain_files() == owner_plain_before
