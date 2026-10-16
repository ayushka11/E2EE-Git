"""Complete SGitLine protocol wrappers: registration, authentication, init, update, pull, share, and accept."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from sgit.codec.lines import (
    ct_from_lines,
    ct_lines,
    decrypt_file,
    encrypt_file,
    split_lines,
)
from sgit.diff.comdiff import (
    apply_ops,
    comdiff_line,
    encrypt_ops,
)
from sgit.client.workspace import WorkspaceClient
from sgit.crypto.keystore import Keystore
from sgit.crypto.primitives import (
    ds_sign,
    kdf,
    pke_dec,
    pke_enc,
)
from sgit.gitio.git import Git
from sgit.gitio.remote import GitUrlRemote, LocalBareRemote, Remote
from sgit.merkle.tree import MerkleTree
from sgit.model.version import (
    AccessFile,
    Tag,
    acs_digest,
    acs_to_bytes,
    parse_acs,
    tag_to_message,
    validate_paths,
    verify_version,
    version_digest,
)
from sgit.service.service import SgitService


def register(
    service: SgitService,
    uid: str,
    github_login: str,
    passphrase: str,
    keystore_path: str | Path,
) -> bytes:
    keystore = Keystore(str(keystore_path), passphrase)
    pk_e, sk_e = keystore.public_ephemeral, keystore.private_ephemeral
    pk_s, sk_s = keystore.public_signing, keystore.private_signing
    return service.register(uid, pk_e, pk_s, github_login)


def authenticate(service: SgitService, uid: str, cred: bytes) -> str:
    return service.authenticate(uid, cred)


def _get_repo_key(
    service: SgitService,
    sid: str,
    keystore: Keystore,
    rid: str,
    owner_uid: str,
    acs: AccessFile | None,
) -> bytes:
    uid = service._uid_for_session(sid)
    if uid == owner_uid:
        return kdf(keystore.master_key, rid)
    if acs is None or uid not in acs.R:
        raise PermissionError(f"User '{uid}' does not have read access to repository '{rid}'")
    ct_shr = acs.R[uid]
    try:
        decrypted = pke_dec(keystore.private_ephemeral, ct_shr)
    except Exception as exc:
        raise PermissionError("Failed to decrypt repository key with user ephemeral key") from exc
    prefix = f"{owner_uid}:".encode("utf-8")
    if not decrypted.startswith(prefix):
        raise ValueError("Decrypted key payload owner prefix does not match expected owner")
    return decrypted[len(prefix):]


def init_repo(
    service: SgitService,
    sid: str,
    keystore: Keystore,
    repo_dir: str | Path,
    remote: Remote | str,
    initial_files: dict[str, bytes] | None = None,
) -> str:
    uid = service._uid_for_session(sid)
    workspace = WorkspaceClient(repo_dir, owner=uid)

    rid = f"{uid}.{os.urandom(8).hex()}"
    workspace.rid = rid

    if isinstance(remote, str):
        remote_obj = GitUrlRemote(remote)
    else:
        remote_obj = remote

    remote_name = f"sgit-{hashlib.sha256(rid.encode()).hexdigest()[:16]}"
    remote_url = remote_obj.create_repo(remote_name)
    service.create_repo_record(sid, rid, remote_url)

    k = kdf(keystore.master_key, rid)

    if initial_files is not None:
        files = dict(initial_files)
    else:
        files = workspace.read_plain_files()
        if not files:
            files["README.md"] = f"# SGit Encrypted Repository: {rid}\n".encode("utf-8")

    validate_paths(files)
    workspace.write_plain_files(files)

    plain_git = Git(workspace.plain_dir, uid)
    plain_git.init()
    plain_git.add_all()
    plain_git.commit("Genesis commit")

    f_ct: dict[str, bytes] = {}
    for rel_path, plain_bytes in files.items():
        f_ct[rel_path] = encrypt_file(k, plain_bytes)

    rh = MerkleTree.from_files(f_ct).root()
    prev = b"\x00" * 32
    digest = version_digest(rid, uid, rh, prev)
    sig = ds_sign(keystore.private_signing, digest)
    tag_msg = tag_to_message(Tag(uid, prev, sig))

    workspace.write_ct_files(f_ct)
    ct_git = Git(workspace.ct_dir, uid)
    ct_git.init()
    ct_git.set_remote(remote_url, "origin")
    ct_git.add_all()
    ct_commit = ct_git.commit(tag_msg)
    ct_git.push("main", force=True)

    workspace.save_state(
        last_ct_commit=ct_commit,
        last_digest=digest,
        remote_url=remote_url,
        rid=rid,
        owner=uid,
    )
    return rid


def update_repo(
    service: SgitService,
    sid: str,
    keystore: Keystore,
    repo_dir: str | Path,
    commit_msg: str = "Update",
) -> str:
    uid = service._uid_for_session(sid)
    workspace = WorkspaceClient(repo_dir)
    state = workspace.load_state()
    if not state:
        raise RuntimeError("Workspace state not found; repository not initialized")

    rid = state["rid"]
    owner = state["owner"]
    last_ct_commit = state["last_ct_commit"]
    last_digest = bytes.fromhex(state["last_digest"])

    ct_git = Git(workspace.ct_dir, uid)
    current_ct_head = ct_git.current_head()
    if current_ct_head != last_ct_commit:
        raise RuntimeError("Local ciphertext repository HEAD does not match verified state; pull first")

    old_ct_files = workspace.read_ct_files()
    acs = parse_acs(old_ct_files[".sgit/acs.json"]) if ".sgit/acs.json" in old_ct_files else None

    if uid != owner and (acs is None or uid not in acs.W):
        raise PermissionError(f"User '{uid}' is not authorized to write to repository '{rid}'")

    k = _get_repo_key(service, sid, keystore, rid, owner, acs)

    new_plain_files = workspace.read_plain_files()
    validate_paths(new_plain_files)

    plain_git = Git(workspace.plain_dir, uid)
    old_plain_commit = plain_git.current_head()
    old_plain_files = plain_git.read_tree(old_plain_commit) if old_plain_commit else {}

    new_ct_files: dict[str, bytes] = {}
    if ".sgit/acs.json" in old_ct_files:
        new_ct_files[".sgit/acs.json"] = old_ct_files[".sgit/acs.json"]

    for rel_path, new_plain in new_plain_files.items():
        if rel_path in old_plain_files and old_plain_files[rel_path] == new_plain and rel_path in old_ct_files:
            # Unchanged: reuse existing ciphertext bytes, zero crypto
            new_ct_files[rel_path] = old_ct_files[rel_path]
        elif rel_path in old_plain_files and rel_path in old_ct_files:
            # Modified: ComDiff line replay
            old_plain = old_plain_files[rel_path]
            old_lines = split_lines(old_plain)
            new_lines = split_lines(new_plain)
            ops = comdiff_line(old_lines, new_lines)
            enc_ops = encrypt_ops(k, ops)
            old_ct_lines_list = ct_lines(old_ct_files[rel_path])
            new_ct_lines_list = apply_ops(old_ct_lines_list, enc_ops)
            new_ct_files[rel_path] = ct_from_lines(new_ct_lines_list)
        else:
            # New file
            new_ct_files[rel_path] = encrypt_file(k, new_plain)

    workspace.write_ct_files(new_ct_files)

    rh = MerkleTree.from_files(new_ct_files).root()
    prev = last_digest
    digest = version_digest(rid, uid, rh, prev)
    sig = ds_sign(keystore.private_signing, digest)
    tag_msg = tag_to_message(Tag(uid, prev, sig))

    ct_git.add_all()
    ct_commit = ct_git.commit(tag_msg)
    ct_git.push("main")

    plain_git.add_all()
    plain_git.commit(commit_msg)

    workspace.save_state(last_ct_commit=ct_commit, last_digest=digest)
    return ct_commit


def pull_repo(
    service: SgitService,
    sid: str,
    keystore: Keystore,
    repo_dir: str | Path,
) -> list[str]:
    uid = service._uid_for_session(sid)
    workspace = WorkspaceClient(repo_dir)
    state = workspace.load_state()
    if not state:
        raise RuntimeError("Workspace state not found")

    rid = state["rid"]
    owner = state["owner"]
    last_ct_commit = state.get("last_ct_commit", "")
    last_digest = bytes.fromhex(state.get("last_digest", "00" * 32))

    ct_git = Git(workspace.ct_dir, uid)
    ct_git.fetch()

    if last_ct_commit:
        rng = f"{last_ct_commit}..origin/main"
        new_commits = ct_git.rev_list(rng)
    else:
        new_commits = ct_git.rev_list("origin/main")

    if not new_commits:
        return []

    def key_lookup(u: str) -> tuple[bytes, bytes]:
        return service.get_keys(u)

    curr_expected_prev = last_digest
    verified_versions = []

    for commit_id in new_commits:
        info = ct_git.commit_info(commit_id)
        files_ct = ct_git.read_tree(commit_id)
        vv = verify_version(
            rid=rid,
            owner_uid=owner,
            files_ct=files_ct,
            commit_msg=str(info["message"]),
            prev_expected=curr_expected_prev,
            key_lookup=key_lookup,
        )
        curr_expected_prev = vv.digest
        verified_versions.append(vv)

    # Fast-forward local ct repository to origin/main
    ct_git._run("reset", "--hard", "origin/main")

    latest_vv = verified_versions[-1]
    k = _get_repo_key(service, sid, keystore, rid, owner, latest_vv.acs)

    plain_files: dict[str, bytes] = {}
    for rel_path, ct_data in latest_vv.files_ct.items():
        if rel_path == ".sgit/acs.json":
            continue
        plain_files[rel_path] = decrypt_file(k, ct_data)

    workspace.write_plain_files(plain_files)

    plain_git = Git(workspace.plain_dir, uid)
    plain_git.init()
    plain_git.add_all()
    plain_git.commit(f"Pulled up to {new_commits[-1][:8]}")

    workspace.save_state(last_ct_commit=new_commits[-1], last_digest=latest_vv.digest)
    return new_commits


def share_repo(
    service: SgitService,
    sid: str,
    keystore: Keystore,
    repo_dir: str | Path,
    recipient_uid: str,
    write: bool = False,
) -> str:
    uid = service._uid_for_session(sid)
    workspace = WorkspaceClient(repo_dir)
    state = workspace.load_state()
    if not state:
        raise RuntimeError("Workspace state not found")

    rid = state["rid"]
    owner = state["owner"]
    last_ct_commit = state["last_ct_commit"]
    last_digest = bytes.fromhex(state["last_digest"])

    if uid != owner:
        raise PermissionError("Only the repository owner can share access")

    k = kdf(keystore.master_key, rid)
    recip_pk_e, recip_pk_s = service.get_keys(recipient_uid)
    ct_shr = pke_enc(recip_pk_e, f"{owner}:".encode("utf-8") + k)

    ct_files = workspace.read_ct_files()
    old_acs = parse_acs(ct_files[".sgit/acs.json"]) if ".sgit/acs.json" in ct_files else AccessFile(R={}, W=[])

    new_R = dict(old_acs.R)
    new_R[recipient_uid] = ct_shr

    new_W = list(old_acs.W)
    if write and recipient_uid not in new_W:
        new_W.append(recipient_uid)

    new_acs_unsigned = AccessFile(R=new_R, W=new_W)
    sigma = ds_sign(keystore.private_signing, acs_digest(rid, new_acs_unsigned))
    new_acs = AccessFile(R=new_R, W=new_W, sigma=sigma)

    ct_files[".sgit/acs.json"] = acs_to_bytes(new_acs)
    workspace.write_ct_files(ct_files)

    rh = MerkleTree.from_files(ct_files).root()
    prev = last_digest
    digest = version_digest(rid, uid, rh, prev)
    sig = ds_sign(keystore.private_signing, digest)
    tag_msg = tag_to_message(Tag(uid, prev, sig))

    ct_git = Git(workspace.ct_dir, uid)
    ct_git.add_all()
    ct_commit = ct_git.commit(tag_msg)
    ct_git.push("main")

    workspace.save_state(last_ct_commit=ct_commit, last_digest=digest)

    oob = service.share_request(sid, rid, recipient_uid, acs_to_bytes(new_acs).decode("utf-8"))
    return oob


def clone_repo(
    service: SgitService,
    sid: str,
    keystore: Keystore,
    repo_dir: str | Path,
    rid: str,
    remote_url: str,
) -> None:
    uid = service._uid_for_session(sid)
    owner = rid.split(".")[0]
    workspace = WorkspaceClient(repo_dir, rid=rid, owner=owner)
    workspace.remote_url = remote_url
    workspace.save_state(
        last_ct_commit="",
        last_digest=b"\x00" * 32,
        remote_url=remote_url,
        rid=rid,
        owner=owner,
    )
    Git.clone(remote_url, workspace.ct_dir, uid)
    pull_repo(service, sid, keystore, repo_dir)


def accept_share(
    service: SgitService,
    sid: str,
    keystore: Keystore,
    repo_dir: str | Path,
    rid: str,
    oob: str,
    remote_url: str,
) -> None:
    service.share_accept(sid, rid, oob)
    clone_repo(service, sid, keystore, repo_dir, rid, remote_url)
