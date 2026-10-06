import base64

from sgit.crypto.primitives import se_dec, se_enc


class CodecError(ValueError):
    """Raised when ciphertext is malformed."""


def split_lines(data: bytes) -> list[bytes]:
    if not data:
        return []
    lines: list[bytes] = []
    start = 0
    for idx, value in enumerate(data):
        if value == 0x0A:  # '\n'
            lines.append(data[start:idx + 1])
            start = idx + 1
    if start < len(data):
        lines.append(data[start:])
    return lines


def join_lines(lines: list[bytes]) -> bytes:
    return b"".join(lines)


def enc_line(k: bytes, line: bytes) -> bytes:
    return base64.b64encode(se_enc(k, line), altchars=None)


def dec_line(k: bytes, ct_line: bytes) -> bytes:
    try:
        raw = base64.b64decode(ct_line, validate=True)
    except Exception as exc:  # pragma: no cover - explicit failure path
        raise CodecError("bad base64 input") from exc
    if len(raw) < 16:
        raise CodecError("ciphertext too short")
    return se_dec(k, raw)


def encrypt_file(k: bytes, data: bytes) -> bytes:
    lines = [enc_line(k, line) for line in split_lines(data)]
    return ct_from_lines(lines)


def decrypt_file(k: bytes, ct: bytes) -> bytes:
    return join_lines([dec_line(k, line) for line in ct_lines(ct)])


def ct_lines(ct: bytes) -> list[bytes]:
    out: list[bytes] = []
    for line in split_lines(ct):
        if line.endswith(b"\n"):
            out.append(line[:-1])
        else:
            out.append(line)
    return out


def ct_from_lines(lines: list[bytes]) -> bytes:
    return b"".join(line + b"\n" for line in lines)
