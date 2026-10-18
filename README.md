# E2EE-Git (SGitLine)

An end-to-end encrypted Git client and service implementation of SGitLine based on the paper ["End-to-End Encrypted Git Services" (Li, Song, Tang, Yung, ACM CCS '25)](https://dl.acm.org/doi/10.1145/3719027.3744815).

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

### Virtual Environment & Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Running the Test Suite

Run all unit, integration, push efficiency, and adversarial tamper tests for the cryptographic engine using:

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

Detailed instructions can be found in [TESTING_GUIDE.md](/TESTING_GUIDE.md).