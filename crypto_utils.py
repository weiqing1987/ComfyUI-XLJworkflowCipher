import base64
import hashlib
import hmac
import json
import platform
import re
import secrets
import uuid
import zlib


PACK_VERSION = 1
PBKDF2_ITERATIONS = 200000
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(data):
        block = hashlib.sha256(
            key + nonce + counter.to_bytes(8, byteorder="big", signed=False)
        ).digest()
        keystream.extend(block)
        counter += 1
    return bytes(left ^ right for left, right in zip(data, keystream))


def _derive_keys(passphrase: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        iterations,
        dklen=64,
    )
    return material[:32], material[32:]


def encrypt_payload(payload: dict, passphrase: str) -> str:
    if not isinstance(payload, dict):
        raise TypeError("WorkflowCipher payload must be a dictionary.")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")

    plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    compressed = zlib.compress(plain, level=9)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(passphrase, salt, PBKDF2_ITERATIONS)
    ciphertext = _xor_stream(compressed, enc_key, nonce)
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    envelope = {
        "v": PACK_VERSION,
        "i": PBKDF2_ITERATIONS,
        "s": _b64_encode(salt),
        "n": _b64_encode(nonce),
        "c": _b64_encode(ciphertext),
        "t": _b64_encode(tag),
    }
    return json.dumps(envelope, separators=(",", ":"))


def decrypt_payload(packed: str, passphrase: str) -> dict:
    if not packed:
        raise ValueError("Encrypted workflow payload is missing.")
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")

    envelope = json.loads(packed)
    version = int(envelope.get("v", 0))
    if version != PACK_VERSION:
        raise ValueError(
            f"Unsupported WorkflowCipher pack version: {version}. Expected {PACK_VERSION}."
        )

    iterations = int(envelope.get("i", 0))
    if iterations <= 0:
        raise ValueError("Encrypted workflow iteration count is invalid.")

    salt = _b64_decode(envelope["s"])
    nonce = _b64_decode(envelope["n"])
    ciphertext = _b64_decode(envelope["c"])
    expected_tag = _b64_decode(envelope["t"])
    enc_key, mac_key = _derive_keys(passphrase, salt, iterations)
    actual_tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, actual_tag):
        raise ValueError("Incorrect passphrase or corrupted encrypted workflow.")

    compressed = _xor_stream(ciphertext, enc_key, nonce)
    try:
        plain = zlib.decompress(compressed)
    except zlib.error as exc:
        raise ValueError("Encrypted workflow payload is invalid.") from exc
    return json.loads(plain.decode("utf-8"))


def sanitize_filename(name: str, fallback: str) -> str:
    candidate = (name or "").strip()
    if not candidate:
        candidate = fallback
    candidate = candidate.replace(" ", "_")
    candidate = _SAFE_FILENAME_RE.sub("_", candidate)
    candidate = candidate.strip("._")
    return candidate or fallback


def current_machine_fingerprint() -> str:
    raw = "|".join(
        [
            platform.system(),
            platform.release(),
            platform.machine(),
            platform.node(),
            hex(uuid.getnode()),
        ]
    ).encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:16]
