import tempfile
from pathlib import Path

import pytest

from sgit.client import protocols
from sgit.client.workspace import WorkspaceClient
from sgit.crypto.keystore import Keystore
from sgit.gitio.git import Git
from sgit.gitio.remote import LocalBareRemote
from sgit.service.service import SgitService


@pytest.fixture
def test_env(tmp_path: Path):
    db_path = tmp_path / "service.db"
    service = SgitService(db_path)
    remote_root = tmp_path / "remotes"
    remote = LocalBareRemote(remote_root)
    return service, remote, tmp_path


def test_registration_and_auth(test_env):
    service, _, tmp_path = test_env
    ks_path = tmp_path / "alice_ks.dat"
    cred = protocols.register(service, "alice", "alice-gh", "pass123", ks_path)
    assert len(cred) == 32

    sid = protocols.authenticate(service, "alice", cred)
    assert len(sid) > 0

    # Verify keystore can reload with same passphrase
    ks_reloaded = Keystore(str(ks_path), "pass123")
    assert len(ks_reloaded.master_key) == 32
    assert len(ks_reloaded.public_ephemeral) == 32
    assert len(ks_reloaded.public_signing) == 32

    # Wrong passphrase fails
    with pytest.raises(ValueError, match="wrong passphrase"):
        Keystore(str(ks_path), "wrong_pass")


def test_init_and_single_user_lifecycle(test_env):
    service, remote, tmp_path = test_env
    ks_path = tmp_path / "owner_ks.dat"
    cred = protocols.register(service, "owner", "owner-gh", "pw", ks_path)
    sid = protocols.authenticate(service, "owner", cred)
    keystore = Keystore(str(ks_path), "pw")

    repo_dir = tmp_path / "owner_repo"
    initial_files = {
        "file1.txt": b"Line 1\nLine 2\nLine 3\n",
        "file2.txt": b"Alpha\nBeta\nGamma\n",
    }
    remote_url = remote.create_repo("test-repo.git")
    rid = protocols.init_repo(service, sid, keystore, repo_dir, remote_url, initial_files)

    ws = WorkspaceClient(repo_dir)
    assert ws.rid == rid
    assert ws.read_plain_files() == initial_files

    # Verify that ciphertext files on remote/local ct do NOT contain plaintext
    ct_files = ws.read_ct_files()
    assert "file1.txt" in ct_files
    assert b"Line 1" not in ct_files["file1.txt"]

    # Now make an update: modify 1 line in file1.txt, add file3.txt
    plain_file1 = ws.plain_dir / "file1.txt"
    plain_file1.write_bytes(b"Line 1\nLine 2 modified\nLine 3\n")
    plain_file3 = ws.plain_dir / "file3.txt"
    plain_file3.write_bytes(b"Brand new file\n")

    old_file2_ct = ct_files["file2.txt"]

    commit_id = protocols.update_repo(service, sid, keystore, repo_dir, "Modify line 2 and add file3")
    assert len(commit_id) > 0

    new_ct_files = ws.read_ct_files()
    # Unchanged file2.txt must have identical ciphertext bytes
    assert new_ct_files["file2.txt"] == old_file2_ct
    # file1.txt must have been updated
    assert new_ct_files["file1.txt"] != ct_files["file1.txt"]
    assert "file3.txt" in new_ct_files

    # Line 1 and Line 3 in file1.txt should have the exact same ciphertext lines (ComDiff property)
    old_lines = ct_files["file1.txt"].splitlines()
    new_lines = new_ct_files["file1.txt"].splitlines()
    assert old_lines[0] == new_lines[0]
    assert old_lines[1] != new_lines[1]
    assert old_lines[2] == new_lines[2]


def test_multi_user_share_and_permissions(test_env):
    service, remote, tmp_path = test_env

    # 1. Register Owner, Writer, and Reader
    owner_ks = tmp_path / "owner_ks.dat"
    owner_cred = protocols.register(service, "owner", "owner-gh", "pw", owner_ks)
    owner_sid = protocols.authenticate(service, "owner", owner_cred)
    owner_keystore = Keystore(str(owner_ks), "pw")

    writer_ks = tmp_path / "writer_ks.dat"
    writer_cred = protocols.register(service, "writer", "writer-gh", "pw", writer_ks)
    writer_sid = protocols.authenticate(service, "writer", writer_cred)
    writer_keystore = Keystore(str(writer_ks), "pw")

    reader_ks = tmp_path / "reader_ks.dat"
    reader_cred = protocols.register(service, "reader", "reader-gh", "pw", reader_ks)
    reader_sid = protocols.authenticate(service, "reader", reader_cred)
    reader_keystore = Keystore(str(reader_ks), "pw")

    # 2. Owner inits repository
    remote_url = remote.create_repo("shared-repo.git")
    owner_repo = tmp_path / "owner_repo"
    initial_files = {"doc.txt": b"Version 1\nSecret data\n"}
    rid = protocols.init_repo(service, owner_sid, owner_keystore, owner_repo, remote_url, initial_files)

    # 3. Owner shares with Writer (read-write) and Reader (read-only)
    writer_oob = protocols.share_repo(service, owner_sid, owner_keystore, owner_repo, "writer", write=True)
    reader_oob = protocols.share_repo(service, owner_sid, owner_keystore, owner_repo, "reader", write=False)

    # 4. Writer accepts share and clones
    writer_repo = tmp_path / "writer_repo"
    protocols.accept_share(service, writer_sid, writer_keystore, writer_repo, rid, writer_oob, remote_url)
    writer_ws = WorkspaceClient(writer_repo)
    assert writer_ws.read_plain_files() == initial_files

    # 5. Reader accepts share and clones
    reader_repo = tmp_path / "reader_repo"
    protocols.accept_share(service, reader_sid, reader_keystore, reader_repo, rid, reader_oob, remote_url)
    reader_ws = WorkspaceClient(reader_repo)
    assert reader_ws.read_plain_files() == initial_files

    # 6. Writer modifies doc.txt and pushes
    (writer_ws.plain_dir / "doc.txt").write_bytes(b"Version 2 - edited by writer\nSecret data\n")
    protocols.update_repo(service, writer_sid, writer_keystore, writer_repo, "Writer update")

    # 7. Owner and Reader pull and see the updated plaintext
    new_commits_owner = protocols.pull_repo(service, owner_sid, owner_keystore, owner_repo)
    assert len(new_commits_owner) >= 1
    owner_ws = WorkspaceClient(owner_repo)
    assert owner_ws.read_plain_files()["doc.txt"] == b"Version 2 - edited by writer\nSecret data\n"

    new_commits_reader = protocols.pull_repo(service, reader_sid, reader_keystore, reader_repo)
    assert len(new_commits_reader) >= 1
    assert reader_ws.read_plain_files()["doc.txt"] == b"Version 2 - edited by writer\nSecret data\n"

    # 8. Reader attempts to push an update: MUST be refused client-side
    (reader_ws.plain_dir / "doc.txt").write_bytes(b"Unauthorized edit by reader\n")
    with pytest.raises(PermissionError, match="not authorized to write"):
        protocols.update_repo(service, reader_sid, reader_keystore, reader_repo, "Reader illegal push")


def test_estimate_push_bytes_efficiency(test_env):
    """Verify headline claim: modifying 1 line in a large file results in small pack bytes."""
    service, remote, tmp_path = test_env
    ks_path = tmp_path / "ks.dat"
    cred = protocols.register(service, "alice", "alice-gh", "pw", ks_path)
    sid = protocols.authenticate(service, "alice", cred)
    keystore = Keystore(str(ks_path), "pw")

    # Create a 2,000-line file (~40 KB)
    large_lines = [f"This is line number {i:04d} with some test payload\n".encode("utf-8") for i in range(2000)]
    large_content = b"".join(large_lines)

    repo_dir = tmp_path / "perf_repo"
    remote_url = remote.create_repo("perf-repo.git")
    rid = protocols.init_repo(service, sid, keystore, repo_dir, remote_url, {"big.txt": large_content})

    ws = WorkspaceClient(repo_dir)
    c1 = ws.load_state()["last_ct_commit"]

    # Modify only 1 line in the middle
    large_lines[1000] = b"This is line number 1000 MODIFIED BY USER\n"
    (ws.plain_dir / "big.txt").write_bytes(b"".join(large_lines))

    c2 = protocols.update_repo(service, sid, keystore, repo_dir, "Edit single line")

    ct_git = Git(ws.ct_dir, "alice")
    push_bytes = ct_git.estimate_push_bytes(c1, c2)

    # In whole-file re-encryption, all 2,000 lines change, requiring >40 KB.
    # In SGitLine, only 1 line changes, so Git delta compression transfers only a few hundred bytes!
    total_file_size = len(large_content)
    # The push bytes should be less than 10% of the full file size
    assert push_bytes < total_file_size * 0.10, f"Push bytes {push_bytes} exceeded 10% of file size {total_file_size}"
