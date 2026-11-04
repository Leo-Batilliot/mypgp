from __future__ import annotations

from math import isqrt

MASK: int = 0xFFFFFFFF
DIGEST_SIZE: int = 32


def first_primes(count: int) -> list[int]:
    primes: list[int] = []
    candidate: int = 2
    while len(primes) < count:
        if all(candidate % p != 0 for p in primes):
            primes.append(candidate)
        candidate += 1
    return primes


# Largest r such that r ** 3 <= n (Newton's method on integers)
def icbrt(n: int) -> int:
    r: int = 1 << ((n.bit_length() + 2) // 3)
    while True:
        s: int = (2 * r + n // (r * r)) // 3
        if s >= r:
            return r
        r = s


# FIPS 180-4 constants: the first 32 bits of the fractional parts of the
# square roots of the first 8 primes (H) and cube roots of the first 64 primes (K).
# Computing them instead of copying them proves there is nothing hidden inside.
H0: tuple[int, ...] = tuple(isqrt(p << 64) & MASK for p in first_primes(8))
K: tuple[int, ...] = tuple(icbrt(p << 96) & MASK for p in first_primes(64))


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK


# Message + 0x80 + zeros + 64-bit big-endian length in bits, up to a multiple of 64 bytes
def pad_message(data: bytes) -> bytes:
    zeros: int = -(len(data) + 9) % 64
    return data + b"\x80" + bytes(zeros) + (len(data) * 8).to_bytes(8, "big")


def compress(state: list[int], chunk: bytes) -> list[int]:
    w: list[int] = [int.from_bytes(chunk[4 * i:4 * i + 4], "big") for i in range(16)]
    for i in range(16, 64):
        s0: int = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1: int = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        big_s1: int = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        choose: int = (e & f) ^ (~e & g)
        t1: int = (h + big_s1 + choose + K[i] + w[i]) & MASK
        big_s0: int = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        majority: int = (a & b) ^ (a & c) ^ (b & c)
        t2: int = (big_s0 + majority) & MASK
        a, b, c, d, e, f, g, h = (t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g
    return [(x + y) & MASK for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sha256(data: bytes) -> bytes:
    state: list[int] = list(H0)
    padded: bytes = pad_message(data)
    for i in range(0, len(padded), 64):
        state = compress(state, padded[i:i + 64])
    return b"".join(word.to_bytes(4, "big") for word in state)
