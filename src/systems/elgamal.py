from __future__ import annotations

import secrets
from typing import ClassVar

from encoding import hex_to_int, int_to_bytes, int_to_hex
from errors import MyPgpError
from math_utils import modexp, modinv
from primes import random_safe_prime
from systems.base import AsymmetricSystem

# Appended to each chunk before it becomes a number: trailing 00 bytes of the chunk
# are no longer the high bytes of the number, so they survive the round trip
MARKER: bytes = b"\x01"


class ElGamalKey:
    # value: y = g^x mod p for a public key, x for a private key
    def __init__(self, value: int, generator: int, prime: int) -> None:
        self.value: int = value
        self.generator: int = generator
        self.prime: int = prime

    @classmethod
    def parse(cls, text: str) -> ElGamalKey:
        parts: list[str] = text.split("-")
        if len(parts) != 3:
            raise MyPgpError(f"invalid ElGamal key '{text}': expected VALUE-GENERATOR-PRIME")
        key: ElGamalKey = cls(*(hex_to_int(part) for part in parts))
        if key.prime < 1 << 16:
            raise MyPgpError("ElGamal prime must be at least 2^16")
        if not 1 < key.generator < key.prime:
            raise MyPgpError("ElGamal generator must be between 2 and P - 1")
        return key

    def __str__(self) -> str:
        return "-".join(int_to_hex(n) for n in (self.value, self.generator, self.prime))

    # p = 2q + 1: g generates the subgroup of order q
    def order(self) -> int:
        return (self.prime - 1) // 2

    # Chunk of message per ciphered pair: one byte for the marker, and the number
    # must stay below p, which has one more byte than chunk + marker
    def chunk_size(self) -> int:
        return (self.prime.bit_length() + 7) // 8 - 2


class ElGamal(AsymmetricSystem):
    name: ClassVar[str] = "elgamal"
    # The message is ciphered as is, trailing line feed included, so deciphering gives back the same file
    strips_newline: ClassVar[bool] = False
    DEFAULT_BITS: ClassVar[int] = 512
    MAX_GENERATOR: ClassVar[int] = 1000

    def __init__(self, key: str | None, block: bool, padding: str | None = None, signed: bool = False) -> None:
        super().__init__(key, block, padding, signed)
        self.elgamal_key: ElGamalKey | None = None if key is None else ElGamalKey.parse(key)

    def require_key(self) -> ElGamalKey:
        if self.elgamal_key is None:
            raise MyPgpError("missing ElGamal key")
        return self.elgamal_key

    # -g P X: P is assumed to be a safe prime (P = 2Q + 1, Q prime), X is the private key
    def generate(self, first: str, second: str) -> bytes:
        p: int = hex_to_int(first)
        x: int = hex_to_int(second)
        if p < 1 << 16:
            raise MyPgpError("P must be at least 2^16")
        if not 1 <= x < (p - 1) // 2:
            raise MyPgpError("X must be between 1 and (P - 1) / 2 - 1")
        return self.make_keys(p, x)

    def generate_random(self, bits: int | None) -> bytes:
        bits = self.DEFAULT_BITS if bits is None else bits
        if bits < 17:
            raise MyPgpError("an ElGamal prime needs at least 17 bits")
        p: int = random_safe_prime(bits)
        return self.make_keys(p, 1 + secrets.randbelow((p - 1) // 2 - 1))

    # g = the smallest square modulo p other than 1: its order divides q, which is prime, so it is q
    @classmethod
    def find_generator(cls, p: int) -> int:
        q: int = (p - 1) // 2
        for g in range(2, cls.MAX_GENERATOR):
            if modexp(g, q, p) == 1:
                return g
        raise MyPgpError("no generator found: P is not a safe prime")

    # public key: y = g^x mod p, private key: x
    @classmethod
    def make_keys(cls, p: int, x: int) -> bytes:
        g: int = cls.find_generator(p)
        public: ElGamalKey = ElGamalKey(modexp(g, x, p), g, p)
        private: ElGamalKey = ElGamalKey(x, g, p)
        return f"public key: {public}\nprivate key: {private}\n".encode()

    # One line "c1-c2" per chunk: c1 = g^r, c2 = m * y^r, with a new random r each time
    def cipher(self, message: bytes) -> bytes:
        key: ElGamalKey = self.require_key()
        size: int = key.chunk_size()
        lines: list[str] = []
        for i in range(0, len(message), size):
            m: int = int.from_bytes(message[i:i + size] + MARKER, "little")
            r: int = 1 + secrets.randbelow(key.order() - 1)
            c1: int = modexp(key.generator, r, key.prime)
            c2: int = m * modexp(key.value, r, key.prime) % key.prime
            lines.append(f"{int_to_hex(c1)}-{int_to_hex(c2)}\n")
        return "".join(lines).encode()

    # s = c1^x = g^(rx) = y^r, the shared secret: m = c2 * s^-1
    def decipher(self, ciphered: bytes) -> bytes:
        key: ElGamalKey = self.require_key()
        try:
            pairs: list[str] = ciphered.decode("ascii").split()
        except UnicodeDecodeError:
            raise MyPgpError("input is not hexadecimal")
        chunks: list[bytes] = []
        for pair in pairs:
            parts: list[str] = pair.split("-")
            if len(parts) != 2:
                raise MyPgpError(f"invalid ciphered pair '{pair}': expected C1-C2")
            c1, c2 = hex_to_int(parts[0]), hex_to_int(parts[1])
            if not 0 < c1 < key.prime or not 0 < c2 < key.prime:
                raise MyPgpError("invalid ciphered pair: values must be between 1 and P - 1")
            shared: int = modexp(c1, key.value, key.prime)
            chunk: bytes = int_to_bytes(c2 * modinv(shared, key.prime) % key.prime)
            if not chunk.endswith(MARKER):
                raise MyPgpError("invalid ciphered message (wrong key?)")
            chunks.append(chunk[:-1])
        return b"".join(chunks)
