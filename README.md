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

## Setup and Installation

### Prerequisites

- Python 3.11+
- Git CLI

### 1. Create a Virtual Environment

```bash
python3 -m venv .venv
```

> [!NOTE]
> On systems where `ensurepip` is not bundled (such as minimal Debian/Ubuntu installations), you can create the environment with `--without-pip` and bootstrap pip:
> ```bash
> python3 -m venv --without-pip .venv
> curl -sSL https://bootstrap.pypa.io/get-pip.py | .venv/bin/python
> ```

### 2. Activate Environment & Install Dependencies

```bash
# Activate the virtual environment
source .venv/bin/activate

# Install the package and all dependencies in editable mode
pip install -e .
```

Dependencies installed via `pyproject.toml`:
- `pycryptodome>=3.20`
- `cryptography`
- `hypothesis`
- `pytest`
- `requests`

## Running the Project

### Running Tests

Run the test suite from the repository root:

```bash
python -m pytest -q
```

### Running the CLI

Run the minimal SGitLine CLI client:

```bash
python -m sgit.cli --help
```
