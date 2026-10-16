# E2EE-Git (SGitLine)

An end-to-end encrypted Git client and service implementation based on the paper **"End-to-End Encrypted Git Services"** (Li, Song, Tang, Yung, ACM CCS '25).

SGitLine enables users to host Git repositories on public or untrusted Git hosts (e.g., GitHub) with complete confidentiality and integrity protection:
- **Zero Plaintext at Rest:** File contents on the remote Git host are stored exclusively as Base64-encoded AES-CTR encrypted lines.
- **Line-Wise Differential Efficiency (ComDiff):** When modifying a few lines in a large file, only the modified lines are re-encrypted and transmitted. Git delta compression operates natively on ciphertext lines, reducing network transfer sizes by up to 90%+ compared to whole-file re-encryption.
- **Merkle DAG & Cryptographic Commit Tags:** Every version is signed using Ed25519 and chained to prior versions via cryptographic digests (`version_digest(rid, uid, rh, prev)`).
- **Fine-Grained Access Control:** Repository keys are hybrid-encrypted (X25519 + AES-GCM) per authorized collaborator and managed via signed `.sgit/acs.json` files.
- **Fail-Closed Verification:** Before any commit is decrypted locally, the client verifies Merkle roots, commit tags, and access signatures. Any unauthorized write or server-side tampering is caught and rejected without altering local files.

---

## Architecture Overview

```
            ┌────────────────────────── Client (per user) ──────────────────────────┐
 user edits │  plain/  (local git repo with plaintext, never pushed)                │
 files here │  ct/     (local git repo of ciphertext, origin = remote Git host)     │
            │  keystore (mk, sk_e, sk_s)   state.json (last verified head/digest)   │
            └──────────────┬─────────────────────────────────────┬──────────────────┘
                           │ git push/fetch (SSH / HTTPS)        │ method calls
                    ┌──────▼──────┐                       ┌──────▼───────────┐
                    │   GitHub    │                       │ SgitService      │
                    │ (ciphertext │                       │ (SQLite): user   │
                    │  repos only)│                       │ directory, tokens│
                    └─────────────┘                       │ sessions, shares │
                                                          └──────────────────┘
```

---

## Setup & Installation

### Prerequisites
- Python 3.11+
- Git CLI

### 1. Virtual Environment & Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Running the Automated Test Suite

Run all unit, integration, push efficiency, and adversarial tamper tests:

```bash
.venv/bin/python -m pytest -v
```

Tests include:
- `tests/test_core.py`: Cryptographic primitives, symmetric encryption, line codec, Merkle DAG, and digital signatures.
- `tests/test_protocols.py`: Registration, authentication, repo initialization, differential commit updates, multi-user sharing (owner/writer/reader), and push size efficiency.
- `tests/test_adversarial.py`: Tamper rejection (ciphertext bit flipping, line deletion, unauthorized writer injection, and fail-closed state preservation).

---

## Real-World Testing Against GitHub

You can test SGitLine in the real world using any existing GitHub repository (e.g. over SSH).

### 1. One-Command Live Demonstration

Run the automated live test runner against your GitHub repository:

```bash
.venv/bin/python tests/test_live_github.py --remote git@github.com:<your-username>/<your-test-repo>.git
```

*(To test in simulated offline mode without GitHub, pass `--remote local`)*.

### 2. Using the `sgit` CLI

The `sgit` command-line tool provides a full Git-like workflow:

```bash
# 1. Register a user and create a passphrase-protected keystore
python -m sgit.cli register --uid alice --passphrase "mypassphrase"

# 2. Initialize an encrypted repository pointing to GitHub
mkdir my-secure-repo && cd my-secure-repo
python -m sgit.cli init . --remote git@github.com:<username>/<repo>.git --passphrase "mypassphrase"

# 3. Add files to the plain/ directory and commit
echo "Confidential data" >> plain/secret.txt
python -m sgit.cli commit . -m "Add confidential secret" --passphrase "mypassphrase"

# 4. Pull and verify changes on another machine
python -m sgit.cli pull . --passphrase "mypassphrase"

# 5. Share repository access with another user (bob)
python -m sgit.cli share . --to bob --write --passphrase "mypassphrase"

# 6. Check status and verified Merkle digest
python -m sgit.cli status .
```

---

## What GitHub Sees

When inspecting the repository on GitHub:
- **File Names:** Visible in cleartext (as specified by SGitLine).
- **File Contents:** Unreadable Base64 ciphertext lines (`[IV: 16B] || [AES-CTR ciphertext]`).
- **Commit Messages:** Cryptographic `sgit-v1` tags:
  ```
  sgit-v1
  uid: alice
  prev: 0000000000000000000000000000000000000000000000000000000000000000
  sig: yUDsF7vLCumlDYf9N/eyQxAGSOsiFF3Ie3j1r+XTR6C4TlLl2K99qY9GBxFDimI//nP5wqJxY8uVNU/NRkRSBg==
  ```
- **Access Control:** `.sgit/acs.json` containing X25519-encrypted repository keys and owner signatures.
