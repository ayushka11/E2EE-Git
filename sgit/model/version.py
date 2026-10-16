import base64
import json
from dataclasses import dataclass

from sgit.crypto.primitives import H


class FormatError(ValueError):
    """Raised when access controls or tags are malformed."""


@dataclass
class AccessFile:
    R: dict[str, bytes]
    W: list[str]
    sigma: bytes | None = None


@dataclass
class Tag:
    uid: str
    prev: bytes
    sig: bytes


def acs_to_bytes(a: AccessFile) -> bytes:
    payload = {
        "v": 1,
        "R": {uid: base64.b64encode(val).decode("ascii") for uid, val in sorted(a.R.items())},
        "W": sorted(a.W),
        "sigma": base64.b64encode(a.sigma or b"").decode("ascii") if a.sigma is not None else "",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_acs(b: bytes) -> AccessFile:
    try:
        payload = json.loads(b.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - explicit failure path
        raise FormatError("invalid ACS JSON") from exc
    if payload.get("v") != 1:
        raise FormatError("wrong ACS version")
    if set(payload.keys()) - {"v", "R", "W", "sigma"}:
        raise FormatError("unexpected ACS fields")
    if not isinstance(payload.get("R"), dict):
        raise FormatError("R must be a dict")
    if not isinstance(payload.get("W"), list):
        raise FormatError("W must be a list")
    r = {}
    for uid, value in payload["R"].items():
        if not isinstance(uid, str):
            raise FormatError("bad key name in R")
        try:
            r[uid] = base64.b64decode(value, validate=True)
        except Exception as exc:  # pragma: no cover - explicit failure path
            raise FormatError("bad base64 in R") from exc
    w = payload["W"]
    if len(set(w)) != len(w):
        raise FormatError("duplicate writers")
    sigma = payload.get("sigma")
    if sigma is None:
        sigma = b""
    try:
        sigma_bytes = base64.b64decode(sigma, validate=True)
    except Exception as exc:  # pragma: no cover - explicit failure path
        raise FormatError("bad base64 sigma") from exc
    return AccessFile(R=r, W=w, sigma=sigma_bytes)


def tag_to_message(t: Tag) -> str:
    return "sgit-v1\nuid: {uid}\nprev: {prev}\nsig: {sig}\n".format(
        uid=t.uid,
        prev=t.prev.hex(),
        sig=base64.b64encode(t.sig).decode("ascii"),
    )


def parse_tag(msg: str) -> Tag:
    lines = msg.splitlines()
    if len(lines) != 4:
        raise FormatError("tag must contain exactly 4 lines")
    if lines[0] != "sgit-v1":
        raise FormatError("tag header mismatch")
    if not lines[1].startswith("uid: "):
        raise FormatError("uid field missing")
    if not lines[2].startswith("prev: "):
        raise FormatError("prev field missing")
    if not lines[3].startswith("sig: "):
        raise FormatError("sig field missing")
    uid = lines[1][5:]
    prev_hex = lines[2][6:]
    sig_text = lines[3][5:]
    try:
        prev = bytes.fromhex(prev_hex)
    except ValueError as exc:  # pragma: no cover - explicit failure path
        raise FormatError("prev is not valid hex") from exc
    try:
        sig = base64.b64decode(sig_text, validate=True)
    except Exception as exc:  # pragma: no cover - explicit failure path
        raise FormatError("sig is not valid base64") from exc
    return Tag(uid=uid, prev=prev, sig=sig)


def acs_digest(rid: str, a: AccessFile) -> bytes:
    unsigned = AccessFile(R=a.R, W=a.W, sigma=None)
    return H(b"acs", rid.encode("utf-8"), acs_to_bytes(unsigned))


def version_digest(rid: str, uid_w: str, rh: bytes, prev: bytes) -> bytes:
    return H(b"version", rid.encode("utf-8"), uid_w.encode("utf-8"), rh, prev)


def validate_paths(files: dict[str, bytes]) -> None:
    for path in files:
        if path in {".git", ".sgit"}:
            raise ValueError("reserved path")
        if path.startswith(".sgit/"):
            if path != ".sgit/acs.json":
                raise ValueError("reserved path")
        if path.startswith("/") or ".." in path.split("/"):
            raise ValueError("illegal path")
        if path.startswith(".git/"):
            raise ValueError("illegal path")


@dataclass
class VerifiedVersion:
    rid: str
    uid: str
    rh: bytes
    digest: bytes
    files_ct: dict[str, bytes]
    acs: AccessFile | None


def verify_version(
    rid: str,
    owner_uid: str,
    files_ct: dict[str, bytes],
    commit_msg: str,
    prev_expected: bytes,
    key_lookup: callable,
) -> VerifiedVersion:
    from sgit.crypto.primitives import ds_verify
    from sgit.merkle.tree import MerkleTree

    validate_paths(files_ct)
    tag = parse_tag(commit_msg)

    if tag.prev != prev_expected:
        raise ValueError(f"prev digest mismatch: expected {prev_expected.hex()}, got {tag.prev.hex()}")

    acs: AccessFile | None = None
    if ".sgit/acs.json" in files_ct:
        acs = parse_acs(files_ct[".sgit/acs.json"])
        _, owner_pk_s = key_lookup(owner_uid)
        if not acs.sigma:
            raise ValueError("missing acs signature")
        if not ds_verify(owner_pk_s, acs_digest(rid, acs), acs.sigma):
            raise ValueError("bad acs signature")
        if tag.uid != owner_uid and tag.uid not in acs.W:
            raise ValueError(f"user '{tag.uid}' is not authorized to write")
    else:
        if tag.uid != owner_uid:
            raise ValueError(f"unauthorized writer '{tag.uid}' on unshared version")

    rh = MerkleTree.from_files(files_ct).root()
    digest = version_digest(rid, tag.uid, rh, prev_expected)
    _, author_pk_s = key_lookup(tag.uid)
    if not ds_verify(author_pk_s, digest, tag.sig):
        raise ValueError(f"bad version signature for user '{tag.uid}'")

    return VerifiedVersion(
        rid=rid,
        uid=tag.uid,
        rh=rh,
        digest=digest,
        files_ct=files_ct,
        acs=acs,
    )

