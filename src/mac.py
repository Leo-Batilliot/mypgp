from __future__ import annotations

from sha256 import DIGEST_SIZE, sha256

# SHA-256 works on 64-byte blocks
HASH_BLOCK_SIZE: int = 64
TAG_SIZE: int = DIGEST_SIZE
INNER_PAD: int = 0x36
OUTER_PAD: int = 0x5C


# HMAC (RFC 2104): H((K ^ opad) || H((K ^ ipad) || data)). A plain H(K || data) is not
# enough: from H(K || data) alone, SHA-256 can be carried on over more data (length extension).
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    if len(key) > HASH_BLOCK_SIZE:
        key = sha256(key)
    key += bytes(HASH_BLOCK_SIZE - len(key))
    inner: bytes = sha256(bytes(b ^ INNER_PAD for b in key) + data)
    return sha256(bytes(b ^ OUTER_PAD for b in key) + inner)


# One sub-key per use: the same key never both ciphers and authenticates. HKDF-Extract
# (RFC 5869): the label is the HMAC key and the key is the data. The other way round, two keys
# differing only by trailing 00 bytes would give the same sub-key, HMAC pads its key with 00.
def derive_key(key: bytes, label: bytes) -> bytes:
    return hmac_sha256(label, key)


# Every byte is compared whatever happens: stopping at the first difference would tell,
# by the time taken, how many bytes of a forged tag are right (timing attack)
def constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    difference: int = 0
    for x, y in zip(a, b):
        difference |= x ^ y
    return difference == 0
