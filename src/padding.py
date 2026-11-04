from __future__ import annotations

import secrets
from typing import Callable

from errors import MyPgpError
from sha256 import DIGEST_SIZE, sha256

# --- PKCS#7 (symmetric) -------------------------------------------------------


# n bytes of value n (1 <= n <= size): always at least one byte, so the padding
# can be removed without ambiguity, even when the message ends with 01 or 00
def pkcs7_pad(data: bytes, size: int) -> bytes:
    if not 1 <= size <= 255:
        raise MyPgpError(f"PKCS#7 padding needs a block of 1 to 255 bytes, not {size}")
    count: int = size - len(data) % size
    return data + bytes([count]) * count


def pkcs7_unpad(data: bytes, size: int) -> bytes:
    if not data or len(data) % size != 0:
        raise MyPgpError("invalid padding")
    count: int = data[-1]
    if not 1 <= count <= size or data[-count:] != bytes([count]) * count:
        raise MyPgpError("invalid padding")
    return data[:-count]


# --- RSA paddings (PKCS#1 v2.2, RFC 8017) -------------------------------------
# An encoded message EM is exactly as long as the modulus (`size` bytes) and starts
# with 00, so that read as a big-endian number it is always smaller than n.

# Bytes each padding adds: a message has at most `size` - overhead bytes
OAEP_OVERHEAD: int = 2 * DIGEST_SIZE + 2
PKCS1_OVERHEAD: int = 11


def check_room(message: bytes, size: int, overhead: int) -> None:
    if len(message) > size - overhead:
        raise MyPgpError(
            f"message too long for this padding: {len(message)} bytes, "
            f"at most {max(0, size - overhead)} with a {size}-byte modulus"
        )


# MGF1: a mask of any length built from SHA-256(seed || counter)
def mgf1(seed: bytes, length: int) -> bytes:
    mask: bytes = b"".join(
        sha256(seed + counter.to_bytes(4, "big"))
        for counter in range((length + DIGEST_SIZE - 1) // DIGEST_SIZE)
    )
    return mask[:length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# EM = 00 || maskedSeed || maskedDB, DB = SHA-256("") || 00...00 || 01 || message.
# The random seed makes two encryptions of the same message different.
def oaep_encode(message: bytes, size: int) -> bytes:
    check_room(message, size, OAEP_OVERHEAD)
    zeros: bytes = bytes(size - len(message) - 2 * DIGEST_SIZE - 2)
    db: bytes = sha256(b"") + zeros + b"\x01" + message
    seed: bytes = secrets.token_bytes(DIGEST_SIZE)
    masked_db: bytes = xor_bytes(db, mgf1(seed, len(db)))
    masked_seed: bytes = xor_bytes(seed, mgf1(masked_db, DIGEST_SIZE))
    return b"\x00" + masked_seed + masked_db


# Every failure gives the same error: telling them apart is what padding oracle attacks exploit
def oaep_decode(em: bytes, size: int) -> bytes:
    if size < OAEP_OVERHEAD or len(em) != size or em[0] != 0:
        raise MyPgpError("invalid padding")
    masked_seed: bytes = em[1:1 + DIGEST_SIZE]
    masked_db: bytes = em[1 + DIGEST_SIZE:]
    seed: bytes = xor_bytes(masked_seed, mgf1(masked_db, DIGEST_SIZE))
    db: bytes = xor_bytes(masked_db, mgf1(seed, len(masked_db)))
    rest: bytes = db[DIGEST_SIZE:].lstrip(b"\x00")
    if db[:DIGEST_SIZE] != sha256(b"") or not rest or rest[0] != 1:
        raise MyPgpError("invalid padding")
    return rest[1:]


# EM = 00 || 02 || PS || 00 || message, PS = at least 8 random non-zero bytes
def pkcs1_encode(message: bytes, size: int) -> bytes:
    check_room(message, size, PKCS1_OVERHEAD)
    ps: bytes = bytes(1 + secrets.randbelow(255) for _ in range(size - len(message) - 3))
    return b"\x00\x02" + ps + b"\x00" + message


def pkcs1_decode(em: bytes, size: int) -> bytes:
    if size < PKCS1_OVERHEAD or len(em) != size or em[:2] != b"\x00\x02":
        raise MyPgpError("invalid padding")
    separator: int = em.find(b"\x00", 2)
    if separator < 10:
        raise MyPgpError("invalid padding")
    return em[separator + 1:]


Encoder = Callable[[bytes, int], bytes]

RSA_PADDINGS: dict[str, tuple[Encoder, Encoder]] = {
    "oaep": (oaep_encode, oaep_decode),
    "pkcs1": (pkcs1_encode, pkcs1_decode),
}
RSA_OVERHEADS: dict[str, int] = {"oaep": OAEP_OVERHEAD, "pkcs1": PKCS1_OVERHEAD}

# --- Signature encoding (EMSA-PKCS1-v1_5 with SHA-256) ------------------------

# DER header saying "what follows is a SHA-256 digest"
SHA256_DIGEST_INFO: bytes = bytes.fromhex("3031300d060960864801650304020105000420")
SIGNATURE_OVERHEAD: int = len(SHA256_DIGEST_INFO) + DIGEST_SIZE + 11


# EM = 00 || 01 || FF...FF (at least 8) || 00 || DigestInfo || SHA-256(data)
def emsa_encode(data: bytes, size: int) -> bytes:
    if size < SIGNATURE_OVERHEAD:
        raise MyPgpError(
            f"RSA key too small to sign: the modulus needs at least {SIGNATURE_OVERHEAD} bytes, not {size}"
        )
    t: bytes = SHA256_DIGEST_INFO + sha256(data)
    return b"\x00\x01" + b"\xff" * (size - len(t) - 3) + b"\x00" + t
