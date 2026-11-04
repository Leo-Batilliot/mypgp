from __future__ import annotations

from typing import ClassVar

from encoding import bytes_to_int, hex_to_int, int_to_bytes, int_to_hex, read_hex
from errors import MyPgpError
from math_utils import gcd, lcm, modexp, modinv
from padding import RSA_OVERHEADS, RSA_PADDINGS, emsa_encode
from primes import random_prime
from systems.base import AsymmetricSystem


class RsaKey:
    def __init__(self, exponent: int, modulus: int) -> None:
        self.exponent: int = exponent
        self.modulus: int = modulus

    @classmethod
    def parse(cls, text: str) -> RsaKey:
        parts: list[str] = text.split("-")
        if len(parts) != 2:
            raise MyPgpError(f"invalid RSA key '{text}': expected EXPONENT-MODULUS")
        exponent: int = hex_to_int(parts[0])
        modulus: int = hex_to_int(parts[1])
        return cls(exponent, modulus)

    def __str__(self) -> str:
        return int_to_hex(self.exponent) + "-" + int_to_hex(self.modulus)

    # Length of the modulus in bytes: the size of a padded block
    def size(self) -> int:
        return (self.modulus.bit_length() + 7) // 8

    # No size check: a value >= n is reduced mod n (a modulus of 0 is rejected by modexp)
    def apply(self, value: int) -> int:
        return modexp(value, self.exponent, self.modulus)

    def check_can_sign(self) -> None:
        emsa_encode(b"", self.size())

    # Signature: the encoded hash of data, raised to the private exponent
    def sign(self, data: bytes) -> int:
        return self.apply(int.from_bytes(emsa_encode(data, self.size()), "big"))

    # The signature raised to the public exponent must give back the encoded hash of data
    def verify(self, data: bytes, signature: int) -> None:
        expected: int = int.from_bytes(emsa_encode(data, self.size()), "big")
        if signature >= self.modulus or self.apply(signature) != expected:
            raise MyPgpError("invalid signature")


# The signature is on the last line, after the ciphered data
def signature_line(signer: RsaKey, data: bytes) -> bytes:
    return (int_to_hex(signer.sign(data)) + "\n").encode()


def split_signature(data: bytes) -> tuple[bytes, int]:
    body, newline, signature = data.rstrip().rpartition(b"\n")
    if not newline or not body.strip():
        raise MyPgpError("missing signature: expected on the last line, after the ciphered message")
    return body, bytes_to_int(read_hex(signature))


class Rsa(AsymmetricSystem):
    name: ClassVar[str] = "rsa"
    FERMAT_PRIMES: ClassVar[tuple[int, ...]] = (65537, 257, 17, 5, 3)
    DEFAULT_BITS: ClassVar[int] = 2048

    # With -s the key is KEY:SIGNER_KEY (signer's private key to cipher, public key to decipher)
    def __init__(self, key: str | None, block: bool, padding: str | None = None, signed: bool = False) -> None:
        super().__init__(key, block, padding, signed)
        self.rsa_key: RsaKey | None = None
        self.signer: RsaKey | None = None
        if key is None:
            return
        if not signed:
            self.rsa_key = RsaKey.parse(key)
            return
        parts: list[str] = key.split(":")
        if len(parts) != 2:
            raise MyPgpError("invalid rsa key for -s: expected RSA_KEY:SIGNER_RSA_KEY")
        self.rsa_key = RsaKey.parse(parts[0])
        self.signer = RsaKey.parse(parts[1])

    def require_key(self) -> RsaKey:
        if self.rsa_key is None:
            raise MyPgpError("missing RSA key")
        return self.rsa_key

    def check_key(self, mode: str) -> None:
        if self.signer is not None:
            self.signer.check_can_sign()

    def generate(self, first: str, second: str) -> bytes:
        p_int: int = hex_to_int(first)
        q_int: int = hex_to_int(second)

        # λ would be <= 0: no public exponent can be chosen
        if p_int < 2 or q_int < 2:
            raise MyPgpError("P and Q must be at least 2")
        return self.format_keys(*self.make_keys(p_int, q_int))

    # Two distinct random primes of half the modulus size each
    def generate_random(self, bits: int | None) -> bytes:
        bits = self.DEFAULT_BITS if bits is None else bits
        if bits < 16:
            raise MyPgpError("an RSA modulus needs at least 16 bits")
        while True:
            p: int = random_prime(bits - bits // 2)
            q: int = random_prime(bits // 2)
            if p == q:
                continue
            try:
                return self.format_keys(*self.make_keys(p, q))
            except MyPgpError:
                continue    # no Fermat prime is coprime with λ: draw again

    @staticmethod
    def format_keys(public: RsaKey, private: RsaKey) -> bytes:
        return f"public key: {public}\nprivate key: {private}\n".encode()

    # n = p * q
    # λ = lcm(p − 1, q − 1)
    # d = e⁻¹ mod λ
    # format:
    # public key: e - n
    # private key: d - n
    @classmethod
    def make_keys(cls, p: int, q: int) -> tuple[RsaKey, RsaKey]:
        n: int = p * q
        carmichael: int = lcm(p - 1, q - 1)
        e: int = cls.choose_exponent(carmichael)
        d: int = modinv(e, carmichael)
        return RsaKey(e, n), RsaKey(d, n)

    # 1 < e < λ and gcd(e, λ) == 1
    @classmethod
    def choose_exponent(cls, carmichael: int) -> int:
        for e in cls.FERMAT_PRIMES:
            if 1 < e < carmichael and gcd(e, carmichael) == 1:
                return e
        raise MyPgpError("no valid public exponent for these primes")

    def transform(self, value: int) -> int:
        return self.require_key().apply(value)

    # Without -p the bytes are read as a little-endian number (subject).
    # With -p they are padded into EM, read as a big-endian number like in PKCS#1.
    def encrypt(self, message: bytes) -> int:
        if self.padding is None:
            return self.transform(bytes_to_int(message))
        encode = RSA_PADDINGS[self.padding][0]
        return self.transform(int.from_bytes(encode(message, self.require_key().size()), "big"))

    def decrypt(self, ciphered: int) -> bytes:
        if self.padding is None:
            return int_to_bytes(self.transform(ciphered))
        size: int = self.require_key().size()
        decode = RSA_PADDINGS[self.padding][1]
        return decode(self.transform(ciphered).to_bytes(size, "big"), size)

    # Longest message that decrypt() gives back intact. Without padding, any number of
    # size - 1 bytes is < n, provided its last byte (the high byte) is not 00.
    def max_message_size(self) -> int:
        size: int = self.require_key().size()
        if self.padding is None:
            return size - 1
        return size - RSA_OVERHEADS[self.padding]

    # c = m ^ e mod n
    def cipher(self, message: bytes) -> bytes:
        c: int = self.encrypt(message)
        output: bytes = (int_to_hex(c) + "\n").encode()
        if self.signer is not None:
            output += signature_line(self.signer, int_to_bytes(c))
        return output

    # m = c ^ d mod n
    def decipher(self, ciphered: bytes) -> bytes:
        if self.signer is not None:
            ciphered, signature = split_signature(ciphered)
            self.signer.verify(int_to_bytes(bytes_to_int(read_hex(ciphered))), signature)
        return self.decrypt(bytes_to_int(read_hex(ciphered))) + b"\n"
