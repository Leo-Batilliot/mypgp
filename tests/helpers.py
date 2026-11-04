"""Shared fixtures and independent oracles.

Expected values in the test suite are computed here with plain Python
(pow, int.to_bytes...) or come from official vectors (FIPS-197, checked with
openssl), never from the output of my_pgp itself.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import resource
import subprocess
import sys
from typing import NamedTuple

from tests import SRC_DIR

# --- Little-endian helpers (independent re-implementation of the convention) --

def le_hex(value: int) -> str:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little").hex()


def le_int(text: str) -> int:
    return int.from_bytes(bytes.fromhex(text), "little")


def word_reverse(data: bytes) -> bytes:
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


# --- XOR oracle ---------------------------------------------------------------

def xor_block_oracle(message: bytes, key: bytes) -> bytes:
    """Epitech convention: reversed message XOR key (both read as little-endian)."""
    return bytes(m ^ k for m, k in zip(message[::-1], key))


def xor_stream_oracle(message: bytes, key: bytes) -> bytes:
    size: int = len(key)
    padded: bytes = message + bytes(-len(message) % size)
    return b"".join(xor_block_oracle(padded[i:i + size], key) for i in range(0, len(padded), size))


def xor_stream_decipher_oracle(ciphered: bytes, key: bytes) -> bytes:
    """Inverse of xor_stream_oracle; a partial last block is padded with zeros first."""
    size: int = len(key)
    padded: bytes = ciphered + bytes(-len(ciphered) % size)
    return b"".join(
        xor_block_oracle(padded[i:i + size], key[::-1]) for i in range(0, len(padded), size)
    )


def zero_pad(data: bytes, size: int) -> bytes:
    return data + bytes(-len(data) % size)


# --- RSA oracle ---------------------------------------------------------------

def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    witnesses: tuple[int, ...] = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in witnesses:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in witnesses:
        x: int = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


class RsaOracle(NamedTuple):
    e: int
    d: int
    n: int

    @property
    def public(self) -> str:
        return f"{le_hex(self.e)}-{le_hex(self.n)}"

    @property
    def private(self) -> str:
        return f"{le_hex(self.d)}-{le_hex(self.n)}"


def rsa_round_trip(value_hex: str, keys: RsaOracle) -> bytes:
    """Bytes recovered by ciphering then deciphering a little-endian number with RSA:
    trailing 00 bytes are lost, and a value >= n comes back reduced mod n."""
    value: int = pow(pow(le_int(value_hex), keys.e, keys.n), keys.d, keys.n)
    return bytes.fromhex(le_hex(value))


def rsa_oracle(p: int, q: int) -> RsaOracle:
    carmichael: int = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    e: int = next(
        e for e in (65537, 257, 17, 5, 3) if 1 < e < carmichael and math.gcd(e, carmichael) == 1
    )
    return RsaOracle(e, pow(e, -1, carmichael), p * q)


# 256-bit primes, little-endian hex (as expected on the command line).
P_HEX: str = "7d30000000000000000000000000000000000000000000000000000000000080"
Q_HEX: str = "216ade3a00000000000000000000000000000000000000000000000000000080"
P: int = le_int(P_HEX)
Q: int = le_int(Q_HEX)
RSA_KEYS: RsaOracle = rsa_oracle(P, Q)

# Tiny primes (211 and 227) used for readable examples.
SMALL_P_HEX: str = "d3"
SMALL_Q_HEX: str = "e3"
SMALL_RSA_KEYS: RsaOracle = rsa_oracle(211, 227)  # n = 47897 (2 bytes): most keys are >= n

# Signer of the -s tests: the other 256-bit primes of the subject appendix (n = 64 bytes)
SIGNER_KEYS: RsaOracle = rsa_oracle(
    le_int("d5da1a8d443812956185f9fe2d8696ea4959d3415967c7a8c5fec34bf7dd53e1"),
    le_int("4fbd36c46bd3fa40ebcef3447a4e2f2f16a6cee884bf889fd58ec5bca6024fe1"),
)

# 1024-bit primes of the subject appendix: n = 256 bytes, enough room for OAEP
BIG_RSA_KEYS: RsaOracle = rsa_oracle(
    le_int(
        "d7c9d58c694fe7ad5d77d888c98d71e7f6a58b4f4dc90582668fd28c0bc20f51"
        "c667ba7b70cb94842006eb5b223065346f7a6bb307ef572fee882c8ef420410b"
        "8b8fa8278ae6a300e63123b28ba1d47259bc308827fcd509585bcee1d98b461f"
        "9eff9c20559540b8c0d6036eff7caf0107d935ecefd5faab87b802bf74c041c8"
    ),
    le_int(
        "e9dfe6b53248c4dc0f391fdda5694bd9f68e111dac5e921a942a157ec92431dc"
        "4833e1a327d36cebcc4ac9b76f2ac2a643db8a04c14963759a800f75915de3ff"
        "beccf86118923b388b352f7e3d20edfd5bb6609fd0b6416da6a56050b000ae9e"
        "14065f06f46ccfaa84c755689e8d95525bb1de8b8a43d380f4db68baac92e0bf"
    ),
)


def modulus_size(keys: RsaOracle) -> int:
    return (keys.n.bit_length() + 7) // 8


def rsa_sign_oracle(data: bytes, keys: RsaOracle) -> int:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017), using hashlib and pow."""
    t: bytes = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(data).digest()
    em: bytes = b"\x00\x01" + b"\xff" * (modulus_size(keys) - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), keys.d, keys.n)


def rsa_raw_decrypt(ciphered: int, keys: RsaOracle) -> bytes:
    """Encoded message EM recovered with pow, before any padding check."""
    return pow(ciphered, keys.d, keys.n).to_bytes(modulus_size(keys), "big")


# --- ElGamal fixtures ---------------------------------------------------------

# Safe primes p = 2q + 1. 65543 = 7 mod 8: 2 is a square, so the generator is 2.
SMALL_SAFE_PRIME: int = 65543
# 256 bits, = 3 mod 8: 2 is not a square, the generator is the next square found
SAFE_PRIME: int = le_int("1b4553be2af7062e72abe9093adf5829a1996ee1426ab7645cb61c4cb95394c0")


def elgamal_generator_oracle(p: int) -> int:
    """Smallest g >= 2 that is a square modulo p (Euler's criterion)."""
    return next(g for g in range(2, p) if pow(g, (p - 1) // 2, p) == 1)


# --- AES vectors (FIPS-197 appendix B / C, verified with openssl) -------------

FIPS_PLAINTEXT: str = "00112233445566778899aabbccddeeff"
FIPS_VECTORS: dict[int, tuple[str, str]] = {
    128: ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    192: ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    256: (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089",
    ),
}
FIPS_APPENDIX_B: tuple[str, str, str] = (
    "2b7e151628aed2a6abf7158809cf4f3c",
    "3243f6a8885a308d313198a2e0370734",
    "3925841d02dc09fbdc118597196a0b32",
)


# --- Modes of operation (NIST SP 800-38A F.2.1 / F.5.1, checked with openssl) -

NIST_KEY: str = "2b7e151628aed2a6abf7158809cf4f3c"
NIST_PLAINTEXT: str = (
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
)
# (IV or first counter block, ciphered)
NIST_CBC: tuple[str, str] = (
    "000102030405060708090a0b0c0d0e0f",
    "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
)
NIST_CTR: tuple[str, str] = (
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
)


# --- HMAC oracle (-a) ---------------------------------------------------------

def hmac_oracle(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def mac_key_oracle(key_hex: str) -> bytes:
    """Tag key of -a: derived from the bytes of the symmetric key (HKDF-Extract)."""
    return hmac_oracle(b"my_pgp authentication key", bytes.fromhex(key_hex))


def split_tag(output: bytes) -> tuple[bytes, bytes]:
    """(ciphered, tag) of one output line of -a: the tag is the last 32 bytes."""
    data: bytes = bytes.fromhex(output.decode().strip())
    return data[:-32], data[-32:]


# --- Running the program ------------------------------------------------------

class Result(NamedTuple):
    code: int
    stdout: bytes
    stderr: bytes


def program() -> list[str]:
    """Command used by functional tests.

    Defaults to `python3 src/` so tests run without building. Set MY_PGP_BIN
    (e.g. MY_PGP_BIN=./my_pgp, as `make tests_run` does) to test the binary.
    """
    binary: str | None = os.environ.get("MY_PGP_BIN")
    if binary:
        return [os.path.abspath(binary)]
    return [sys.executable, SRC_DIR]


def run(args: list[str], stdin: bytes = b"", memory_limit: int | None = None) -> Result:
    """memory_limit: address space limit of the program in bytes (like `ulimit -v`)."""
    def limit_memory() -> None:
        if memory_limit is not None:
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))

    proc = subprocess.run(
        program() + args, input=stdin, capture_output=True, timeout=60, check=False,
        preexec_fn=limit_memory,
    )
    return Result(proc.returncode, proc.stdout, proc.stderr)
