# SGitLine Implementation Plan

Based on: *End-to-End Encrypted Git Services* (Li, Song, Tang, Yung, CCS '25).
Scope: **SGitLine only**, a learning/reproduction exercise. Built bottom-up; each milestone ends with a **gate** (tests that must pass before moving on).

---

## 1. Decisions (locked in)

| # | Topic | Decision |
|---|---|---|
| 1 | Purpose | Learning / reproduction |
| 2 | Scope | SGitLine only (SGitChar not planned) |
| 3 | Features | Exactly the paper's: Reg, Auth, Init, Update, Pull, ShareI, ShareII, read/write separation, unforgeability. **No** revocation, merge, or delete extension |
| 4 | Evaluation | No benchmarking for now (push-size measurement helper is included, since it validates the core claim) |
| 5 | Language | Python 3.11+ |
| 6 | Crypto library | `pycryptodome` (imports as `Crypto`) |
| 7 | Git access | `git` CLI via `subprocess` |
| 8 | Tests | `pytest` + `hypothesis` |
| 9 | Service state | In-process Python class backed by SQLite (stdlib `sqlite3`) |
| 10 | Git remote | **Real GitHub from the start**, behind a `Remote` interface (local bare repo is the second implementation, for offline tests and tamper simulation) |
| 11 | Auth | Token-based (random token issued at registration, kept secret by the user) |
| 12 | PKI | Server-hosted public-key directory as stand-in for out-of-band exchange (known trust gap, see §3) |
| 13 | Π_SE | AES-CTR, random 128-bit IV per line (paper's design) |
| 14 | Π_DS | Ed25519 |
| 15 | Π_PKE | X25519 + HKDF + AES-GCM hybrid (fallback: RSA-OAEP if your pycryptodome lacks X25519 key agreement) |
| 16 | KDF | HKDF-SHA256 |
| 17 | Hash | SHA-256 |
| 18 | Key storage | Passphrase-protected local keystore (scrypt + AES-GCM) |
| 19 | File names | In the clear (paper allows) |
| 20 | Binary files | Treated as a single "line" |
| 21 | Line endings | Preserve exact bytes (`\r\n`, missing trailing newline) |
| 22 | Ciphertext line encoding | Base64, one encrypted line per Git line |
| 23 | Access file | `.sgit/acs.json` in the ciphertext tree |
| 24 | Tag location | Commit message |
| 25 | Owner write rights | Owner is implicitly a writer; `σ_acs` check skipped when `f_acs` is empty |
| 26 | ShareI signature | Sign the **new** `f'_acs` (the paper's figure appears to sign the old one, likely a typo) |
| 27 | Rollback/reordering | Chain each version's signed digest to the previous one (§M5) |
| 28 | Concurrency | Linear history only; fail on divergence |
| 29 | Merkle structure | Mirrors directory hierarchy, domain-separated, incremental update API |
| 30 | File removal in Update | Omit the file from the new version (note: the paper defers deletion to an extension, so this is a deliberate small deviation; switch to carry-over if you want literal fidelity) |
| 31 | Plan detail | Function signatures and test cases per milestone |

---

## 2. Architecture

```
            ┌────────────────────────── client (per user) ──────────────────────────┐
 user edits │  plain/  (local git repo, never pushed)                                │
 files here │  ct/     (local git repo of ciphertext, origin = GitHub private repo)  │
            │  keystore (mk, sk_e, sk_s)   state.json (last verified head/digest)   │
            └──────────────┬─────────────────────────────────────┬───────────────────┘
                           │ git push/fetch (HTTPS + PAT)        │ method calls
                    ┌──────▼──────┐                       ┌──────▼───────────┐
                    │   GitHub    │                       │ SgitService      │
                    │ (ciphertext │                       │ (SQLite): user   │
                    │  repos only)│                       │ directory, tokens│
                    └─────────────┘                       │ sessions, shares │
                                                          └──────────────────┘
```

- **GitHub** stores only ciphertext repos. It never sees plaintext, but does see file paths, commit authorship timestamps, file sizes, and edit positions (SGitLine's "weaker" confidentiality).
- **SgitService** is the paper's "server" logic that GitHub has no equivalent for: key directory, sessions, pending shares, access list `A`. It is an in-process class, so "multiple users" means multiple client objects/processes on one machine sharing one SQLite file.
- **Two tokens per user:** the *service token* (`cred`, used by `Π_auth`) and a *GitHub PAT* (used only for git transport and the GitHub API). Keep them separate in code.

### Suggested layout

```
sgit/
  crypto/primitives.py     # SE, KDF, PKE, DS, hash
  crypto/keystore.py
  codec/lines.py           # line split/encrypt/decrypt
  diff/comdiff.py          # Op, comdiff_line, apply_ops
  merkle/tree.py
  model/version.py         # AccessFile, Tag, signed digests, parsers
  gitio/git.py             # git CLI wrapper
  gitio/remote.py          # Remote protocol, LocalBareRemote, GitHubRemote
  service/service.py       # SgitService (SQLite)
  client/workspace.py      # state.json, plain/ct dirs
  client/protocols.py      # reg, auth, init, update, pull, share1, share2
  cli.py
tests/
  unit/  integration/  adversarial/  github/
```

pytest markers: `unit`, `integration` (local bare remote), `adversarial`, `github` (network; skipped unless env vars set).

---

## 3. Known trust gaps and conventions

- **Directory trust.** The server-hosted key directory means a corrupted server could substitute public keys. The paper assumes this can't happen. Documented limitation; optional mitigation in Stretch S1.
- **Rid format.** `rid = f"{owner_uid}.{nonce_hex_16bytes}"`; `uid` matches `^[a-z0-9][a-z0-9_-]{0,31}$`. GitHub repo name is derived: `sgit-` + first 16 hex chars of `SHA256(rid)`.
- **Hash encoding.** Never concatenate fields raw. `H(label, *parts)` length-prefixes every part (8-byte big-endian) after a fixed domain label.
- **Leaks accepted by SGitLine** (document and test): file paths, file count, line count, line lengths (ciphertext length reveals plaintext length), edit positions and types.
- **Reserved paths:** `.git`, `.sgit/` (only `acs.json` allowed). Reject `..`, absolute paths, symlinks. Regular files only.

---

## M0: Project setup

**Build**
- `pyproject.toml`; dependencies: `pycryptodome>=3.20` (verify X25519/Ed25519 support in your installed version), `hypothesis`, `pytest`, `requests` (GitHub API).
- `git --version` check; pytest markers; `conftest.py` with fixtures: `tmp_workspace`, `local_remote`, `make_user(uid)`.
- **GitHub test setup** (do now, needed from M6):
  - Create 2-3 **throwaway** GitHub accounts (owner, writer, reader) so sharing is testable end to end.
  - Create a PAT for each. A classic PAT with `repo` and `delete_repo` scopes is the simplest (verify current GitHub docs, since fine-grained token capabilities for creating/deleting repos have restrictions).
  - Export `SGIT_GH_OWNER_TOKEN`, `SGIT_GH_WRITER_TOKEN`, `SGIT_GH_READER_TOKEN` and the matching `*_LOGIN` variables. Never commit tokens.
  - Test repos are always private, named with a `sgit-test-` prefix, and deleted in fixture teardown.
  - For tamper simulation, branch protection must be off so force-push works.

**Gate:** `pytest` runs (zero tests is fine), GitHub-marked tests skip cleanly without env vars.

---

## M1: Crypto primitives

**API**
```python
# primitives.py
def H(label: bytes, *parts: bytes) -> bytes                       # SHA-256, length-prefixed
def kdf(mk: bytes, rid: str) -> bytes                             # HKDF-SHA256, 32-byte key, info = b"sgit/v1/repo-key" + rid
def se_keygen() -> bytes                                          # 32 random bytes
def se_enc(k: bytes, m: bytes) -> bytes                           # iv(16) || AES-CTR(m); random IV
def se_dec(k: bytes, c: bytes) -> bytes
def ds_keygen() -> tuple[bytes, bytes]                            # (sk, pk) Ed25519, serialized
def ds_sign(sk: bytes, msg: bytes) -> bytes
def ds_verify(pk: bytes, msg: bytes, sig: bytes) -> bool          # returns False, never raises on bad input
def pke_keygen() -> tuple[bytes, bytes]                           # (sk, pk) X25519
def pke_enc(pk: bytes, m: bytes) -> bytes                         # eph_pub || nonce || GCM(ct||tag)
def pke_dec(sk: bytes, c: bytes) -> bytes                         # raises DecryptError on failure
```
Notes: AES-CTR in pycryptodome: `AES.new(k, AES.MODE_CTR, nonce=b"", initial_value=iv)` for a full random 128-bit IV. All verification functions fail closed.

**Tests**
- Round trip for each primitive (hypothesis over arbitrary bytes, including empty).
- `se_enc` twice on the same input gives different outputs; both decrypt.
- Wrong key: `se_dec` yields garbage (CTR has no integrity, so assert it != plaintext and do not expect an exception); `pke_dec` raises.
- Flip any single bit of a signature or message: `ds_verify` is False.
- `kdf` deterministic; differs across `rid`; differs across `mk`.
- `H("a", b"x", b"yz") != H("a", b"xy", b"z")` (encoding is unambiguous).

**Gate:** all green. No module outside `crypto/` imports `Crypto.*`.

---

## M2: Line codec

Each plaintext "line" is the bytes up to and including `\n` (so `\r\n` and a missing final newline are preserved exactly). Binary files (a NUL byte in the first 8000 bytes, as Git does) are one single line. The ciphertext file is `base64(se_enc(k, line)) + "\n"` per line.

**API**
```python
def split_lines(data: bytes) -> list[bytes]          # keepends; b"" -> []
def join_lines(lines: list[bytes]) -> bytes
def enc_line(k: bytes, line: bytes) -> bytes         # base64 text, WITHOUT newline
def dec_line(k: bytes, ct_line: bytes) -> bytes
def encrypt_file(k: bytes, data: bytes) -> bytes     # ct file bytes
def decrypt_file(k: bytes, ct: bytes) -> bytes
def ct_lines(ct: bytes) -> list[bytes]               # ct file -> list of ct lines (no newline)
def ct_from_lines(lines: list[bytes]) -> bytes
```

**Tests**
- Property: `decrypt_file(k, encrypt_file(k, d)) == d` for arbitrary bytes.
- Edge cases explicitly: empty file, `"\n"`, no trailing newline, `\r\n` mixed with `\n`, a file of only blank lines, binary blob, very long single line.
- `len(ct_lines(encrypt_file(k, d))) == len(split_lines(d))`.
- Identical plaintext lines in one file give distinct ciphertext lines.
- Malformed ciphertext (bad base64, too short for an IV) raises a typed `CodecError`, not a crash.

**Gate:** property tests pass with the default hypothesis budget.

---

## M3: ComDiff_line and operations

Operations follow the paper: `("insert", i, m)` and `("delete", i)`, applied **sequentially**, `O_n(...O_1(f))`.

**Convention (document in the module docstring):** indices are 0-based and relative to the list *as it is at the moment the op is applied*. Generating from `difflib` opcodes left to right, every op for opcode `(i1,i2,j1,j2)` uses position `j1` for the deletes, then `j1, j1+1, ...` for the inserts.

**API**
```python
@dataclass(frozen=True)
class Op(Generic[T]):
    kind: Literal["insert", "delete"]
    idx: int
    m: T | None = None

def comdiff_line(old: Sequence[bytes], new: Sequence[bytes]) -> list[Op[bytes]]
def apply_ops(seq: Sequence[T], ops: Iterable[Op[T]]) -> list[T]    # generic: plaintext OR ciphertext lines
def encrypt_ops(k: bytes, ops: list[Op[bytes]]) -> list[Op[bytes]]  # inserts get enc_line(k, m); deletes unchanged
```
Use `difflib.SequenceMatcher(None, old, new, autojunk=False)`. (Quadratic worst case is fine for learning; note it.)

**Tests**
- Property: `apply_ops(old, comdiff_line(old, new)) == new` for random list pairs.
- Identical inputs give `[]`.
- Pure append, pure prepend, pure delete, full replace, duplicated lines, empty to non-empty, non-empty to empty.
- **Ciphertext replay property (the core correctness property of Update):** for random `old`, `new`, `k`:
  `ct_old = [enc_line(k,l) for l in old]`, `ops' = encrypt_ops(k, comdiff_line(old,new))`,
  `[dec_line(k,c) for c in apply_ops(ct_old, ops')] == new`.
- Lines untouched by the diff keep byte-identical ciphertext after replay.
- `apply_ops` raises on out-of-range indices (malformed ops from an attacker must not crash weirdly).

**Gate:** all properties pass.

---

## M4: Merkle DAG

The signature must cover a whole version but cost O(changed path), not O(repo size).

**Design**
- Leaf (file): `H("leaf", name, H("content", bytes))`
- Directory node: `H("dir", name, *[(kind, child_name, child_hash)] sorted by child_name)`
- Root = hash of the (unnamed) root directory. The tree covers **all** tracked ciphertext files **including `.sgit/acs.json`** (the paper's `MerkleDAG(f^ct, f_acs)`), and excludes `.git`.

**API**
```python
class MerkleTree:
    @classmethod
    def from_files(cls, files: dict[str, bytes]) -> "MerkleTree"
    def root(self) -> bytes
    def update_file(self, path: str, content: bytes | None) -> None   # None = remove; recomputes only ancestors
```

**Tests**
- Deterministic regardless of insertion order.
- Any of these changes the root: edit a byte, add a file, remove a file, rename a file, move a file between directories, swap contents of two files.
- A file `a/b` vs a directory `a` containing `b` vs a file named `a/b` in a different structure do not collide (domain separation).
- Property: random sequence of `update_file` calls equals `from_files` on the final dict.
- Counter-instrumented hashing test: updating one leaf at depth d recomputes at most d+1 node hashes (plus siblings' cached hashes are reused).

**Gate:** all green.

---

## M5: Version data model and signed digests

A version is `(f_ct, f_acs, f_tag)`.

**Formats**
- `.sgit/acs.json` (canonical JSON: sorted keys, no whitespace, base64 for bytes):
  `{"v":1, "R": {uid: b64(ct_shr)}, "W": [uid,...], "sigma": b64}`. Absent file means empty `f_acs` (genesis).
- Commit message (the tag), exact format, strictly parsed:
  ```
  sgit-v1
  uid: <uid_w>
  prev: <hex of previous version digest, or 64 zeros for genesis>
  sig: <base64>
  ```
- Signed digest of a version: `digest = H("version", rid, uid_w, rh, prev)` where `rh` is the Merkle root. This is the paper's `Hash(rid‖uid‖rh)` plus the `prev` link (decision 27). `sig = ds_sign(sk_s(uid_w), digest)`.
- `σ_acs` signs `H("acs", rid, canonical(R), canonical(W))` with the owner's key.

**API**
```python
@dataclass class AccessFile: R: dict[str, bytes]; W: list[str]; sigma: bytes | None
@dataclass class Tag: uid: str; prev: bytes; sig: bytes
def acs_to_bytes(a) -> bytes;  def parse_acs(b: bytes) -> AccessFile        # strict; raises FormatError
def tag_to_message(t) -> str;  def parse_tag(msg: str) -> Tag               # strict; raises FormatError
def acs_digest(rid, a) -> bytes
def version_digest(rid, uid_w, rh, prev) -> bytes
def validate_paths(files: dict[str, bytes]) -> None                         # reserved/illegal paths
```

**Tests**
- Round trips; strict rejection of: extra fields, duplicate keys, wrong version, non-hex `prev`, bad base64, duplicate uids in `W`, trailing garbage, CRLF-mangled commit messages.
- `version_digest` changes when any one input changes.

**Gate:** malformed inputs raise `FormatError` and never any other exception type (hypothesis fuzz on the parsers).

---

## M6: Git I/O layer and remotes

**Git wrapper**
```python
class Git:
    def __init__(self, path: Path, identity: str, token: str | None = None)
    def init(self, bare=False); def clone(self, url: str, dest: Path) -> "Git"
    def add_all(self); def commit(self, message: str) -> str          # returns commit id
    def push(self, branch="main", force=False); def fetch(self)
    def rev_list(self, rng: str, first_parent=True) -> list[str]
    def commit_info(self, c: str) -> CommitInfo                        # id, parents, message
    def read_tree(self, c: str) -> dict[str, bytes]                    # via ls-tree -r -z + cat-file --batch
    def write_tree(self, files: dict[str, bytes])                       # replace working tree (deleting removed files)
    def estimate_push_bytes(self, old: str, new: str) -> int           # git rev-list --objects old..new | git pack-objects --thin --stdout, count bytes
```
- Fix author/committer name+email to the uid and set `GIT_TERMINAL_PROMPT=0`.
- **Credentials:** pass the PAT per command with `-c http.extraHeader="Authorization: Basic <b64('x-access-token:'+PAT)>"` (or a `GIT_ASKPASS` helper). Never write the token into the remote URL or `.git/config`. Mind that command-line args can be visible to other local users, which is acceptable for this exercise.

**Remote interface**
```python
class Remote(Protocol):
    def create_repo(self, name: str) -> str                         # returns clone URL; private
    def delete_repo(self, name: str) -> None
    def invite(self, name: str, login: str, perm: Literal["pull","push"]) -> str   # returns invitation id
    def accept(self, invitation_id: str, token: str) -> None
class LocalBareRemote  # creates bare repos in a temp dir; invite/accept are no-ops
class GitHubRemote     # GitHub REST API: create repo (private), delete, add collaborator, accept invitation
```
Check the current GitHub REST docs for the exact endpoints (create repo, add collaborator, accept repository invitation, delete repo).

**Tests**
- (integration, local bare) commit, push, clone, `read_tree` at several past commits; `write_tree` removes deleted files; `estimate_push_bytes` is small for a small change.
- (github) smoke test: create private repo, push, clone with a second token after `invite`/`accept`, delete repo. Skipped without env vars.

**Gate:** you can round-trip arbitrary files through `ct/` and a remote, with no crypto involved, on both remote types.

---

## M7: Service, Reg/Auth, keystore

**Keystore:** file holding `mk`, `sk_e`, `sk_s` (plus public keys), encrypted with a key from scrypt(passphrase) using AES-GCM; loading with a wrong passphrase raises.

**Service (SQLite)**
```python
class SgitService:
    def register(self, uid, pk_e, pk_s, github_login) -> bytes            # returns cred (random 32 bytes); store only H(cred)
    def authenticate(self, uid, cred) -> str                              # returns fresh sid; sessions expire
    def get_keys(self, uid) -> tuple[bytes, bytes]                        # (pk_e, pk_s)
    def create_repo_record(self, sid, rid, gh_name) -> None               # fails if rid exists (Rid check)
    def get_repo(self, sid, rid) -> RepoRecord                            # only if uid in A[rid]
    def share_request(self, sid, rid, uid_re, acs: str) -> str            # owner only; stores pending (uid_re, oob, acs); returns oob
    def share_accept(self, sid, rid, oob) -> None                         # receiver only; moves pending -> A[rid]
```
- **Every** method except `register`/`authenticate` first checks the session (`ses[sid] -> uid`), implementing footnote 5's "fail on empty session state".
- Compare creds in constant time; never log them.

**Client protocol functions** `register(...)`, `authenticate(...)` wire the keystore, `km = (mk, pk_e, sk_e, pk_s, sk_s)`, and the service.

**Tests**
- Duplicate `uid` rejected; invalid `uid` format rejected.
- Wrong token rejected; correct token yields a session; two parallel sessions for one user coexist.
- Any repo operation with a missing/unknown/expired `sid` fails.
- Service DB contains no raw creds.
- Keystore: wrong passphrase fails; tampered file fails.

**Gate:** correctness equation for Auth from the paper holds: `reg` then `auth` with the issued cred always succeeds.

---

## M8: Init

Follow Figure 6 exactly.

1. Require session. `rid = f"{uid}.{nonce_hex}"`, `k = kdf(mk, rid)`.
2. For each plaintext file: `f_ct[path] = encrypt_file(k, data)`.
3. `rh = MerkleTree(f_ct + {}).root()` (no `acs.json` at genesis), `prev = 0x00*32`, `digest = version_digest(rid, uid, rh, prev)`, `sig = ds_sign(sk_s, digest)`.
4. Create GitHub repo (`remote.create_repo`), record it in the service, `ct/` commit with message `tag_to_message(...)`, push.
5. Create local `plain/` repo with the plaintext and commit; write `state.json`: `{rid, owner, last_ct_commit, last_digest, ct_to_plain: {...}}`.

**Tests**
- (integration) From a fresh clone of the remote, decrypt manually with `k` and recover the exact plaintext tree.
- Duplicate `rid` rejected by the service.
- Init with an empty plaintext tree, a binary file, nested directories, and an illegal path (`.sgit/x`, `../x`) behaves as specified.
- (github) same flow against real GitHub.

**Gate:** the genesis version verifies with the verification routine you'll build in M10 (write the verifier function now as a pure function over `(rid, files, msg, prev, key lookup)`, and call it in this test).

---

## M9: Update

1. Preconditions: session active; `ct/` HEAD == `state.last_ct_commit` == remote HEAD (otherwise "pull first"); user is owner or in `acs.W`.
2. Derive `k`: owner uses `kdf(mk, rid)`; others `pke_dec(sk_e, acs.R[uid])` and check the embedded sender uid equals the owner.
3. Compare old plaintext (`plain/` HEAD) with new plaintext (working tree), per path:
   - **Unchanged:** reuse the existing ciphertext bytes, do no crypto.
   - **Modified:** `ops = comdiff_line(old_lines, new_lines)`, `ops' = encrypt_ops(k, ops)`, new ciphertext = `apply_ops(ct_lines_old, ops')`.
   - **New:** `encrypt_file`.
   - **Removed:** omit from the new version (decision 30).
4. `acs.json` is carried over byte-identically (writers cannot change it).
5. Recompute the root incrementally (`update_file` for each changed path), compute `prev = last_digest`, sign, commit with the tag, push.
6. Commit the plaintext in `plain/`; update `state.json`.

**Tests**
- After an update, decrypting `ct/` equals the new plaintext exactly (random edit scripts via hypothesis).
- Unchanged files' ciphertext bytes are identical, and their blobs' Git object ids don't change.
- **Headline claim:** change one line in a large file; `estimate_push_bytes` is small, on the order of the changed line plus tree/commit overhead, and far smaller than a re-encryption of the file (compare against a naive baseline `encrypt_file` with a fresh key). Assert a loose ratio, e.g. under 5% of file size, rather than an exact byte count.
- Update by a non-writer is refused client-side.
- Updating while behind the remote is refused.
- (github) one real update round trip.

**Gate:** replay property from M3 holds end to end through Git.

---

## M10: Pull with verification

```python
def verify_version(rid, owner_uid, files_ct, msg, prev_expected, prev_acs, key_lookup) -> VerifiedVersion
```
Pull algorithm:

1. `fetch`. Compute `new = rev_list(state.last_ct_commit..origin/main)`.
2. **Ancestry check:** `last_ct_commit` must be an ancestor of `origin/main`, otherwise fail (rollback or fork detected). The remote head being *behind* the stored head is also a failure.
3. For each commit in order (oldest first), **before decrypting anything**:
   - Exactly one parent (zero for the genesis only); no merge commits.
   - `validate_paths`; parse `acs.json` (if present) and the tag, strictly.
   - `rh = Merkle(files incl. acs.json)`; `digest = version_digest(rid, tag.uid, rh, prev_expected)`; require `tag.prev == prev_expected`.
   - If `acs` is non-empty: `ds_verify(pk_s[owner], acs_digest(rid, acs), acs.sigma)`.
   - Writer check: `tag.uid == owner or tag.uid in acs.W`.
   - `ds_verify(pk_s[tag.uid], digest, tag.sig)`.
   - If `acs` changed relative to the previous version, the author must be the owner. (Optional hardening: `acs` may only grow, since revocation is out of scope.)
   - Genesis: author is the owner named in `rid`, `acs` is empty, `prev` is zero.
4. Only after **all** missing versions verify: derive `k`, decrypt each version, write `plain/`, commit, and atomically update `state.json`. If any version fails, change nothing.

**Tests**
- Multi-version catch-up; a fresh `clone` reconstructs the full history and equals the owner's plaintext history.
- Pull with nothing new is a no-op.
- Fail-closed behavior: after an injected bad version, `plain/` and `state.json` are unchanged.
- Verifier is a pure function, so unit-test it directly with hand-built versions.

**Gate:** a second client (owner's second device with the same keystore) stays in sync across several updates.

---

## M11: Sharing and multi-user

**ShareI (owner only)**
1. Require `uid == owner`. `ct_shr = pke_enc(pk_e[uid_re], uid_bytes || k)`.
2. `R' = R ∪ {uid_re: ct_shr}`; `W' = W ∪ {uid_re}` if write access. Sign the **new** `acs'` (decision 26). Same `f_ct`, new Merkle root (the root includes `acs.json`), new tag chained to the previous digest, commit and push.
3. `oob = service.share_request(...)`. On GitHub: `remote.invite(repo, login_re, "push" if write else "pull")`. Return `oob` (delivered to the receiver out of band, e.g. you paste it).

**ShareII (receiver)**
1. `service.share_accept(sid, rid, oob)`; `remote.accept(invitation_id, receiver_token)`.
2. Clone the repo and run the full verifying pull from genesis (M10). The key comes from `pke_dec(sk_e, acs.R[uid])`; check the embedded sender uid equals the owner.

**Tests** (offline with `LocalBareRemote`; mirrored in `github`-marked tests with 3 accounts)
- Owner, writer, reader scenario:
  - Writer pushes; owner and reader pull and see the change.
  - Reader's client refuses to update.
  - A push authored by the reader (crafted manually with the reader's valid signature) is **rejected by the owner's and writer's Pull** (`uid_w ∉ W`).
- Two writers alternating updates keep a linear history (the second must pull first).
- Accepting with a wrong `oob` or by the wrong user fails; double accept fails.
- Correctness equation from the paper (§2): a shared repo pulled by the receiver equals the sender's contents.

**Gate:** the three-user scenario passes locally; the GitHub variant passes at least once.

---

## M12: Adversarial and confidentiality tests

Treat this as a core deliverable. **Simulating a corrupted server:** locally, edit the bare repo directly; against GitHub, force-push a tampered history using a token with write access (the owner's PAT plays the corrupted-server role). Each test then asserts that an honest client's Pull **fails and leaves local state unchanged**.

| Attack | Expected |
|---|---|
| Delete a file from the newest version | Merkle root / signature mismatch |
| Inject an extra file | same |
| Swap contents of two files | same |
| Flip one bit in one ciphertext line | same |
| Reorder lines within a file | same |
| Modify `acs.json` (add an `R` entry or a `W` member) | `σ_acs` or root mismatch |
| Server substitutes `acs.json` from an older version | root mismatch (and monotonicity check if enabled) |
| Reader forges a version naming the owner in the tag | signature fails |
| Reader pushes a version with own valid signature | `uid_w ∉ W` |
| Writer modifies `acs.json` and re-signs only the tag | `σ_acs` fails / author not owner |
| Edit commit message fields (`uid`, `prev`, `sig`) | strict parse or signature failure |
| Drop the newest version(s) (rollback) | detected on a client that already saw the newer head; **cannot** be detected by a brand-new client (document this honestly) |
| Reorder two valid versions | `prev` chain mismatch |
| Fork (two different children of one version) | second client fails ancestry check |
| Merge commit or non-linear history | rejected |

Add a **property test:** take a valid history, apply a random mutation to a random file/line/field in a random non-genesis version, and assert that Pull fails (or the mutated tree equals the original).

**Confidentiality sanity checks (document the expected "leaks")**
- Equal lines produce unequal ciphertext lines.
- The edit position and operation type **are visible** in the Git diff between two ct versions (this is SGitLine's weaker confidentiality; write a test that demonstrates it so you understand it).
- Line lengths and file names are visible.
- Ciphertext of version n+1 reveals which lines were unchanged.

**Out of scope but listed:** key substitution in the directory (see S1).

---

## M13: CLI, docs, and GitHub end-to-end

- Commands: `sgit register`, `login`, `init <dir>`, `commit` (plain → ct, push), `pull`, `share <rid> <uid> --read|--write`, `accept <rid> <oob>`, `status`, `clone <rid>`.
- Config file for service DB path, GitHub login/token (read from env or a `0600` file, never from the CLI args).
- Write a short `README` explaining the trust model, what GitHub sees, and the known gaps (§3).
- Final GitHub e2e script: three accounts, init, share (read and write), update, pull, and one tamper-by-force-push scenario.

**Gate:** the e2e script runs cleanly and the cleanup fixture deletes all test repos.

---

## Paper ambiguities and how this plan resolves them

1. **Genesis writer:** `Init` sets `f_acs = ∅` but Pull requires `uid_w ∈ f_acs.W`. Resolved: owner is implicitly a writer; `σ_acs` skipped for empty `f_acs`.
2. **ShareI signature:** the figure signs `f_acs.W ‖ f_acs.R` of the *old* file. Resolved: sign the new `f'_acs`, bound to `rid`.
3. **File removal:** the figure carries over old files absent from the new version. Resolved: omit them (deviation; see decision 30).
4. **Merkle structure and name binding:** unspecified in the paper. Resolved in M4.
5. **Concurrency/merge:** not covered. Resolved: linear history, fail on divergence.
6. **Malformed input:** the proofs assume well-formed ciphertexts. Resolved: strict parsing and verify-before-decrypt in M5/M10.
7. **History integrity:** the paper signs `rid‖uid‖rh` only. Resolved with the `prev` chain.
8. **Key hygiene in ShareI:** the paper encrypts `uid‖k` but doesn't say what the receiver checks. Resolved: receiver verifies the embedded uid equals the owner.
9. **Key directory:** discussed in §3.

---

## Milestone dependency order and checkpoints

```
M0 → M1 → M2 → M3 ─┐
          M1 → M4 ─┼→ M5 → M8 → M9 → M10 → M11 → M12 → M13
          M6 (needs M0) ┘   M7 (needs M1) ┘
```
- **After M3:** the core line-wise-encryption idea is demonstrably correct in memory.
- **After M10:** you have a working single-user system on real GitHub (good demo point).
- **After M12:** you have the paper's actual security story, tested.

---

## Stretch goals (not required)

- **S1. Key pinning (TOFU):** store a fingerprint of each peer's `(pk_e, pk_s)` on first use; fail on change; add `sgit fingerprint` for out-of-band comparison. This narrows the directory trust gap.
- **S2. Benchmarking:** Trivial-enc-sign and deterministic (Git-crypt-style) baselines; compare push bytes, compute time, and storage growth over ~50 commits of a few public repos (mirrors the paper's Tables 2-3 and Figure 9).
- **S3. Git-native hardening:** compare using Git's own tree hash vs. your Merkle design.
- **S4. SGitChar,** if you want to extend later; the Merkle/signature/sharing layers are reusable unchanged.
