#!/usr/bin/env python3

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from sgit.client import protocols
from sgit.client.workspace import WorkspaceClient
from sgit.crypto.keystore import Keystore
from sgit.service.service import SgitService


DEFAULT_CONFIG_DIR = Path.home() / ".sgit"
DEFAULT_KEYSTORE_PATH = DEFAULT_CONFIG_DIR / "keystore.dat"
DEFAULT_DB_PATH = DEFAULT_CONFIG_DIR / "service.db"
DEFAULT_SESSION_FILE = DEFAULT_CONFIG_DIR / "session.json"


def _get_config_dir() -> Path:
    config_dir = Path(os.environ.get("SGIT_CONFIG_DIR", DEFAULT_CONFIG_DIR))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def _get_service(db_path: str | None = None) -> SgitService:
    path = db_path or os.environ.get("SGIT_DB_PATH", str(_get_config_dir() / "service.db"))
    return SgitService(path)


def _get_passphrase(args: argparse.Namespace) -> str:
    pw = getattr(args, "passphrase", None) or os.environ.get("SGIT_PASSPHRASE")
    if pw:
        return pw
    return getpass.getpass("Enter keystore passphrase: ")


def _get_keystore(args: argparse.Namespace, passphrase: str | None = None) -> Keystore:
    ks_path = getattr(args, "keystore", None) or os.environ.get("SGIT_KEYSTORE_PATH", str(_get_config_dir() / "keystore.dat"))
    pw = passphrase or _get_passphrase(args)
    return Keystore(ks_path, pw)


def _save_session(uid: str, sid: str, cred_hex: str) -> None:
    session_file = _get_config_dir() / "session.json"
    session_file.write_text(json.dumps({"uid": uid, "sid": sid, "cred": cred_hex}, indent=2), encoding="utf-8")


def _get_active_session(service: SgitService, args: argparse.Namespace) -> tuple[str, str]:
    # Returns (uid, sid)
    if getattr(args, "uid", None) and getattr(args, "cred", None):
        uid = args.uid
        cred = bytes.fromhex(args.cred)
        sid = protocols.authenticate(service, uid, cred)
        return uid, sid

    session_file = _get_config_dir() / "session.json"
    if session_file.exists():
        try:
            data = json.loads(session_file.read_text(encoding="utf-8"))
            uid = data["uid"]
            cred = bytes.fromhex(data["cred"])
            sid = protocols.authenticate(service, uid, cred)
            return uid, sid
        except Exception:
            pass
    raise RuntimeError("Not logged in. Please run 'sgit login' or 'sgit register' first.")


def cmd_register(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    ks_path = args.keystore or str(_get_config_dir() / "keystore.dat")
    pw = _get_passphrase(args)
    cred = protocols.register(service, args.uid, args.login or args.uid, pw, ks_path)
    cred_hex = cred.hex()
    sid = protocols.authenticate(service, args.uid, cred)
    _save_session(args.uid, sid, cred_hex)
    print(f"Registered user '{args.uid}' successfully.")
    print(f"Your secret credential token (SAVE THIS): {cred_hex}")


def cmd_login(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    cred = bytes.fromhex(args.cred)
    sid = protocols.authenticate(service, args.uid, cred)
    _save_session(args.uid, sid, args.cred)
    print(f"Authenticated as '{args.uid}'. Session active.")


def cmd_init(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    uid, sid = _get_active_session(service, args)
    keystore = _get_keystore(args)
    repo_dir = Path(args.dir).resolve()
    rid = protocols.init_repo(service, sid, keystore, repo_dir, args.remote)
    print(f"Initialized encrypted repository {rid} in {repo_dir}")
    print(f"Plaintext directory: {repo_dir / 'plain'}")
    print(f"Ciphertext directory: {repo_dir / 'ct'}")


def cmd_commit(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    uid, sid = _get_active_session(service, args)
    keystore = _get_keystore(args)
    repo_dir = Path(args.dir).resolve()
    commit_id = protocols.update_repo(service, sid, keystore, repo_dir, args.message)
    print(f"Committed and pushed encrypted version: {commit_id}")


def cmd_pull(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    uid, sid = _get_active_session(service, args)
    keystore = _get_keystore(args)
    repo_dir = Path(args.dir).resolve()
    new_commits = protocols.pull_repo(service, sid, keystore, repo_dir)
    if new_commits:
        print(f"Successfully pulled and verified {len(new_commits)} new version(s).")
    else:
        print("Already up to date.")


def cmd_share(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    uid, sid = _get_active_session(service, args)
    keystore = _get_keystore(args)
    repo_dir = Path(args.dir).resolve()
    oob = protocols.share_repo(service, sid, keystore, repo_dir, args.to, write=args.write)
    perm = "read-write" if args.write else "read-only"
    print(f"Shared repository with '{args.to}' ({perm}).")
    print(f"Out-of-band invitation code (send to recipient): {oob}")


def cmd_accept(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    uid, sid = _get_active_session(service, args)
    keystore = _get_keystore(args)
    repo_dir = Path(args.dir).resolve()
    protocols.accept_share(service, sid, keystore, repo_dir, args.rid, args.oob, args.remote)
    print(f"Accepted share for '{args.rid}' and cloned into {repo_dir}")


def cmd_clone(args: argparse.Namespace) -> None:
    service = _get_service(args.db)
    uid, sid = _get_active_session(service, args)
    keystore = _get_keystore(args)
    repo_dir = Path(args.dir).resolve()
    protocols.clone_repo(service, sid, keystore, repo_dir, args.rid, args.remote)
    print(f"Cloned and decrypted '{args.rid}' into {repo_dir}")


def cmd_status(args: argparse.Namespace) -> None:
    repo_dir = Path(args.dir).resolve()
    workspace = WorkspaceClient(repo_dir)
    state = workspace.load_state()
    if not state:
        print(f"No SGit repository found in {repo_dir}")
        return
    print(f"Repository ID:       {state.get('rid')}")
    print(f"Owner:               {state.get('owner')}")
    print(f"Remote URL:          {state.get('remote_url')}")
    print(f"Last CT Commit:      {state.get('last_ct_commit')}")
    print(f"Last Version Digest: {state.get('last_digest')}")
    plain_files = workspace.read_plain_files()
    print(f"Plaintext files ({len(plain_files)}):")
    for f in sorted(plain_files.keys()):
        print(f"  {f} ({len(plain_files[f])} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(description="SGitLine: End-to-End Encrypted Git Client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # register
    p_reg = subparsers.add_parser("register", help="Register a new user and generate keys")
    p_reg.add_argument("--uid", required=True, help="Unique user identifier")
    p_reg.add_argument("--login", default="", help="GitHub username")
    p_reg.add_argument("--passphrase", help="Keystore passphrase")
    p_reg.add_argument("--keystore", help="Path to keystore file")
    p_reg.add_argument("--db", help="Path to service SQLite database")

    # login
    p_login = subparsers.add_parser("login", help="Authenticate with user token")
    p_login.add_argument("--uid", required=True, help="User identifier")
    p_login.add_argument("--cred", required=True, help="Hex-encoded credential token")
    p_login.add_argument("--db", help="Path to service SQLite database")

    # init
    p_init = subparsers.add_parser("init", help="Initialize a new encrypted repository")
    p_init.add_argument("dir", nargs="?", default=".", help="Repository directory")
    p_init.add_argument("--remote", required=True, help="Remote Git repository URL (SSH/HTTPS)")
    p_init.add_argument("--passphrase", help="Keystore passphrase")
    p_init.add_argument("--keystore", help="Path to keystore file")
    p_init.add_argument("--db", help="Path to service SQLite database")

    # commit
    p_commit = subparsers.add_parser("commit", help="Encrypt changes and push to remote")
    p_commit.add_argument("dir", nargs="?", default=".", help="Repository directory")
    p_commit.add_argument("-m", "--message", default="Update", help="Commit message")
    p_commit.add_argument("--passphrase", help="Keystore passphrase")
    p_commit.add_argument("--keystore", help="Path to keystore file")
    p_commit.add_argument("--db", help="Path to service SQLite database")

    # pull
    p_pull = subparsers.add_parser("pull", help="Fetch, verify, and decrypt remote changes")
    p_pull.add_argument("dir", nargs="?", default=".", help="Repository directory")
    p_pull.add_argument("--passphrase", help="Keystore passphrase")
    p_pull.add_argument("--keystore", help="Path to keystore file")
    p_pull.add_argument("--db", help="Path to service SQLite database")

    # share
    p_share = subparsers.add_parser("share", help="Share repository with another user")
    p_share.add_argument("dir", nargs="?", default=".", help="Repository directory")
    p_share.add_argument("--to", required=True, help="Recipient user identifier")
    p_share.add_argument("--write", action="store_true", help="Grant write permissions")
    p_share.add_argument("--passphrase", help="Keystore passphrase")
    p_share.add_argument("--keystore", help="Path to keystore file")
    p_share.add_argument("--db", help="Path to service SQLite database")

    # accept
    p_accept = subparsers.add_parser("accept", help="Accept repository share and clone")
    p_accept.add_argument("dir", nargs="?", default=".", help="Target repository directory")
    p_accept.add_argument("--rid", required=True, help="Repository identifier")
    p_accept.add_argument("--oob", required=True, help="Out-of-band invitation code")
    p_accept.add_argument("--remote", required=True, help="Remote Git repository URL")
    p_accept.add_argument("--passphrase", help="Keystore passphrase")
    p_accept.add_argument("--keystore", help="Path to keystore file")
    p_accept.add_argument("--db", help="Path to service SQLite database")

    # clone
    p_clone = subparsers.add_parser("clone", help="Clone an authorized encrypted repository")
    p_clone.add_argument("dir", nargs="?", default=".", help="Target directory")
    p_clone.add_argument("--rid", required=True, help="Repository identifier")
    p_clone.add_argument("--remote", required=True, help="Remote Git URL")
    p_clone.add_argument("--passphrase", help="Keystore passphrase")
    p_clone.add_argument("--keystore", help="Path to keystore file")
    p_clone.add_argument("--db", help="Path to service SQLite database")

    # status
    p_status = subparsers.add_parser("status", help="Show workspace status and verified state")
    p_status.add_argument("dir", nargs="?", default=".", help="Repository directory")

    args = parser.parse_args()

    commands = {
        "register": cmd_register,
        "login": cmd_login,
        "init": cmd_init,
        "commit": cmd_commit,
        "pull": cmd_pull,
        "share": cmd_share,
        "accept": cmd_accept,
        "clone": cmd_clone,
        "status": cmd_status,
    }

    try:
        commands[args.command](args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
