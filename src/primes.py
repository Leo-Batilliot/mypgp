from __future__ import annotations

import secrets

from errors import MyPgpError
from math_utils import modexp

# Probability that a composite passes every round: at most 4 ** -ROUNDS
ROUNDS: int = 40


def small_primes(limit: int) -> tuple[int, ...]:
    sieve: bytearray = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytes(len(range(i * i, limit, i)))
    return tuple(i for i in range(limit) if sieve[i])


# Trial division by these primes discards most candidates before Miller-Rabin
SMALL_PRIMES: tuple[int, ...] = small_primes(2000)


def has_small_factor(n: int) -> bool:
    return any(n % p == 0 and n != p for p in SMALL_PRIMES)


# Miller-Rabin: write n - 1 = d * 2^s with d odd. For a prime n and any base a,
# a^d = 1 or a^(d * 2^r) = -1 for some r < s. A base that breaks this proves n composite.
def is_probable_prime(n: int, rounds: int = ROUNDS) -> bool:
    if n < 2:
        return False
    if n in SMALL_PRIMES:
        return True
    if has_small_factor(n):
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        a: int = 2 + secrets.randbelow(n - 3)
        x: int = modexp(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# Exactly `bits` bits and odd. The two top bits are set: the product of two such numbers
# of a and b bits always has a + b bits (>= 1.5 * 2^(a-1) * 1.5 * 2^(b-1) > 2^(a+b-1))
def random_odd(bits: int) -> int:
    return secrets.randbits(bits) | (3 << (bits - 2)) | 1


def random_prime(bits: int) -> int:
    if bits < 2:
        raise MyPgpError("a prime needs at least 2 bits")
    if bits == 2:
        return 2 + secrets.randbelow(2)
    while True:
        candidate: int = random_odd(bits)
        if is_probable_prime(candidate):
            return candidate


# Safe prime p = 2q + 1 with q prime: the squares modulo p form a group of prime order q
def random_safe_prime(bits: int) -> int:
    if bits < 3:
        raise MyPgpError("a safe prime needs at least 3 bits")
    while True:
        q: int = random_odd(bits - 1)
        p: int = 2 * q + 1
        if has_small_factor(q) or has_small_factor(p):
            continue
        if is_probable_prime(q, 1) and is_probable_prime(p, 1) and is_probable_prime(q) and is_probable_prime(p):
            return p
