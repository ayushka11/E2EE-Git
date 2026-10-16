#!/usr/bin/env python3
"""Live Real-World Test Runner for SGitLine E2EE Git.

Demonstrates end-to-end encryption against real Git hosts (e.g. GitHub over SSH).
- Encrypts files line-by-line using AES-CTR and Base64 encoding.
- Generates and signs Ed25519 version tags and Merkle trees.
- Pushes ciphertext to the remote Git repository.
- Clones and verifies integrity, then decrypts plaintext in a second workspace.

Usage:
    # Test against a real GitHub repository via SSH:
    python tests/test_live_github.py --remote git@github.com:<username>/<test-repo>.git

    # Test in local simulation mode (no remote required):
    python tests/test_live_github.py --remote local
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from sgit.client import protocols
from sgit.client.workspace import WorkspaceClient
from sgit.crypto.keystore import Keystore
from sgit.gitio.git import Git
from sgit.gitio.remote import LocalBareRemote
from sgit.service.service import SgitService


def run_live_test(remote_url: str, passphrase: str = "secure_demo_passphrase", workdir: Path | None = None) -> None:
    temp_dir_obj = None
    if workdir is None:
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="sgit_live_")
        base_dir = Path(temp_dir_obj.name)
    else:
        base_dir = Path(workdir)
        base_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print(" SGitLine: Live Real-World End-to-End Encryption Demonstration")
    print("=" * 70)
    print(f"Working Directory: {base_dir}")

    db_path = base_dir / "service.db"
    service = SgitService(db_path)

    # 1. Setup Remote
    if remote_url == "local" or not remote_url:
        local_remote_dir = base_dir / "bare_remote.git"
        bare_remote = LocalBareRemote(base_dir)
        target_remote = bare_remote.create_repo("bare_remote.git")
        print(f"Mode: Local Bare Remote (Simulated GitHub Server): {target_remote}")
    else:
        target_remote = remote_url
        print(f"Mode: Real Git Remote: {target_remote}")

    # 2. Register User & Keystore
    print("\n[Step 1] Registering User & Generating Local Cryptographic Keys...")
    ks_path = base_dir / "owner_keystore.dat"
    uid = "alice"
    cred = protocols.register(service, uid, "alice-gh", passphrase, ks_path)
    sid = protocols.authenticate(service, uid, cred)
    keystore = Keystore(str(ks_path), passphrase)
    print(f"  ✓ User: {uid}")
    print(f"  ✓ Public Ephemeral (X25519): {keystore.public_ephemeral.hex()[:24]}...")
    print(f"  ✓ Public Signing (Ed25519):   {keystore.public_signing.hex()[:24]}...")
    print(f"  ✓ Master Key (scrypt-derived): {keystore.master_key.hex()[:24]}...")

    # 3. Create Plaintext Files & Initialize Encrypted Repo
    print("\n[Step 2] Initializing Repository and Encrypting Files...")
    repo_dir = base_dir / "alice_repo"
    initial_files = {
        "README.md": b"# Confidential Project\nConfidential research findings.\nDo not disclose.\n",
        "data.csv": b"id,name,metric\n1,Alpha,98.5\n2,Beta,92.1\n3,Gamma,95.4\n",
    }
    print("  Plaintext files to encrypt:")
    for f, content in initial_files.items():
        print(f"    - {f} ({len(content)} bytes)")

    rid = protocols.init_repo(service, sid, keystore, repo_dir, target_remote, initial_files)
    ws_alice = WorkspaceClient(repo_dir)
    print(f"  ✓ Initialized Repository ID: {rid}")
    print(f"  ✓ Pushed genesis encrypted version to {target_remote}")

    # 4. Inspect What Git / GitHub Sees
    print("\n[Step 3] Inspecting Encrypted State (What GitHub / Git Host Sees):")
    ct_files = ws_alice.read_ct_files()
    ct_git = Git(ws_alice.ct_dir, uid)
    info = ct_git.commit_info("HEAD")
    print(f"  Git Commit Hash: {info['id']}")
    print(f"  Commit Tag Message on Git:")
    for line in str(info['message']).splitlines():
        print(f"    | {line}")

    print("\n  Ciphertext blob for 'README.md' on Git:")
    for ct_line in ct_files["README.md"].splitlines():
        print(f"    [CT] {ct_line.decode('ascii')}")

    # 5. Differential Line-Wise Update
    print("\n[Step 4] Performing Line-Wise Differential Edit (ComDiff)...")
    plain_readme = ws_alice.plain_dir / "README.md"
    updated_readme = b"# Confidential Project\nConfidential research findings.\nUPDATED: New secret discovery added here.\nDo not disclose.\n"
    plain_readme.write_bytes(updated_readme)

    c1 = ws_alice.load_state()["last_ct_commit"]
    c2 = protocols.update_repo(service, sid, keystore, repo_dir, "Add new secret discovery")
    push_bytes = ct_git.estimate_push_bytes(c1, c2)

    print(f"  ✓ Pushed new version commit: {c2}")
    print(f"  ✓ Bandwidth transferred: {push_bytes} bytes (only modified line was re-encrypted)")

    # 6. Clone & Pull in a Second Workspace (Simulating Another Device / User)
    print("\n[Step 5] Cloning & Decrypting in a Second Workspace...")
    clone_dir = base_dir / "alice_device2"
    protocols.clone_repo(service, sid, keystore, clone_dir, rid, target_remote)
    ws_clone = WorkspaceClient(clone_dir)

    decrypted_files = ws_clone.read_plain_files()
    print(f"  ✓ Successfully verified signatures, Merkle tree root, and version chain!")
    print(f"  ✓ Decrypted {len(decrypted_files)} files in second workspace:")
    for name, content in decrypted_files.items():
        print(f"    - {name}: {len(content)} bytes")

    # 7. Verification Check
    expected_files = {
        "README.md": updated_readme,
        "data.csv": initial_files["data.csv"],
    }
    assert decrypted_files == expected_files, "Decrypted files do not match expected plaintext!"
    print("\n[Step 6] Verification Passed Byte-for-Byte!")
    print("=" * 70)
    print(" SUCCESS: End-to-end encrypted Git roundtrip completed cleanly!")
    print(" Plaintext never touches GitHub; only Base64 AES-CTR and Ed25519 signatures.")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Live Real-World Test for SGitLine E2EE Git")
    parser.add_argument(
        "--remote",
        default="local",
        help="Git remote URL (e.g. git@github.com:username/repo.git or 'local' for simulation)",
    )
    parser.add_argument("--passphrase", default="secure_demo_passphrase", help="Keystore passphrase")
    parser.add_argument("--workdir", help="Optional persistent directory for testing")
    args = parser.parse_args()

    workdir = Path(args.workdir) if args.workdir else None
    run_live_test(args.remote, args.passphrase, workdir)


if __name__ == "__main__":
    main()
