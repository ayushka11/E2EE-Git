# E2EE-Git

This repository is a simple SGitLine learning implementation based on the paper "End-to-End Encrypted Git Services".

The goal is intentionally narrow: implement the core SGitLine ideas in a clear, readable Python form, following the milestone plan in `sgitline_implementation_plan.md` without adding unrelated extensions.

## Included in this build

- Basic hash, symmetric encryption, digital signatures, and X25519-style hybrid encryption helpers
- Simple line-wise encryption and decryption logic
- Sequence-based diff and replay operations
- A lightweight Merkle tree abstraction
- Version/tag data model helpers
- A thin `git` CLI wrapper and local bare remote for learning exercises
- SQLite-backed service/session state
- A passphrase-protected local keystore

## Trust and scope notes

- This is a learning / reproduction project, not a production-ready secure Git service.
- GitHub and the service host are treated as honest-but-curious placeholders, matching the paper’s SGitLine assumptions.
- The code deliberately keeps the structure simple and easy to understand.

## Local verification

Run the project tests from the repo root with:

```bash
python -m pytest -q
```

This project uses a local virtual environment at `.venv` for dependency isolation.
