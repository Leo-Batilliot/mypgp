from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from typing import ClassVar

from encoding import bytes_to_hex, hex_to_bytes, hex_to_int, int_to_bytes, int_to_hex, read_hex
from errors import MyPgpError
from systems.aes import Aes
from systems.base import CryptoSystem, SymmetricSystem
from systems.rsa import Rsa, RsaKey, signature_line, split_signature
from systems.xor import Xor


class Pgp(CryptoSystem, ABC):
    symmetric: ClassVar[type[SymmetricSystem]]

    # SYMMETRIC_KEY:RSA_KEY, plus :SIGNER_RSA_KEY with -s.
    # random_key: -k, the symmetric key is drawn at random and left out of the key.
    # operation (-m) and authenticated (-a) are passed on to the symmetric system.
    def __init__(
        self, key: str | None, block: bool, padding: str | None = None, signed: bool = False,
        operation: str = "ecb", authenticated: bool = False, random_key: bool = False,
    ) -> None:
        super().__init__(key, block, padding, signed)
        if key is None:
            raise MyPgpError("missing key")
        self.operation: str = operation
        self.authenticated: bool = authenticated
        names: list[str] = ["RSA_KEY"] if random_key else ["SYMMETRIC_KEY", "RSA_KEY"]
        if signed:
            names.append("SIGNER_RSA_KEY")
        parts: list[str] = key.split(":")
        if len(parts) != len(names):
            raise MyPgpError(f"invalid {self.name} key: expected {':'.join(names)}")
        self.sym_key: str | None = None if random_key else parts.pop(0)
        self.rsa: Rsa = Rsa(parts[0], block, padding)
        self.signer: RsaKey | None = RsaKey.parse(parts[1]) if signed else None

    # -p pads the symmetric key through RSA, and the message with PKCS#7 in stream mode
    # (in block mode the message is exactly one block, and CTR pads nothing)
    def symmetric_system(self, key: str) -> SymmetricSystem:
        padding: str | None = None if self.block or self.operation == "ctr" else self.padding
        return self.symmetric(key, self.block, padding, False, self.operation, self.authenticated)

    # -c needs a valid symmetric key (with -k, room in RSA for a random one),
    # -d only a number (the ciphered symmetric key)
    def check_key(self, mode: str) -> None:
        if self.sym_key is None:
            self.random_key_size(1)
        elif mode == "-c":
            self.symmetric_system(self.sym_key).check_key(mode)
        else:
            hex_to_bytes(self.sym_key)
        if self.signer is not None:
            self.signer.check_can_sign()

    # Size of a random symmetric key (-k) for a message of `message_size` bytes
    @abstractmethod
    def random_key_size(self, message_size: int) -> int:
        ...

    # -k: random bytes, the last one (the high byte of the number ciphered by RSA) never 00,
    # so that the key comes back through RSA with its length, even without -p
    def random_key(self, message_size: int) -> str:
        size: int = self.random_key_size(message_size)
        return bytes_to_hex(secrets.token_bytes(size - 1) + bytes([1 + secrets.randbelow(255)]))

    # The signature covers the ciphered key and the ciphered message. The key length
    # comes first, otherwise moving bytes from one to the other would keep the signature valid.
    @staticmethod
    def signed_data(ciphered_key: int, ciphered_message: bytes) -> bytes:
        key_bytes: bytes = int_to_bytes(ciphered_key)
        return len(key_bytes).to_bytes(4, "big") + key_bytes + ciphered_message

    def cipher(self, message: bytes) -> bytes:
        sym_key: str = self.random_key(len(message)) if self.sym_key is None else self.sym_key
        ciphered_message: bytes = self.symmetric_system(sym_key).cipher(message)
        ciphered_key: int = self.rsa.encrypt(hex_to_bytes(sym_key))
        output: bytes = (int_to_hex(ciphered_key) + "\n").encode() + ciphered_message
        if self.signer is not None:
            output += signature_line(self.signer, self.signed_data(ciphered_key, read_hex(ciphered_message)))
        return output

    # Without -p, the key is used exactly as recovered through RSA: its trailing 00 bytes
    # are lost, and a key >= n comes back as key mod n. With -p it comes back intact.
    def decipher(self, ciphered: bytes) -> bytes:
        if self.sym_key is None:
            raise MyPgpError("-k only works with -c: deciphering needs the ciphered symmetric key")
        ciphered_key: int = hex_to_int(self.sym_key)
        if self.signer is not None:
            ciphered, signature = split_signature(ciphered)
            self.signer.verify(self.signed_data(ciphered_key, read_hex(ciphered)), signature)
        sym_key: bytes = self.rsa.decrypt(ciphered_key)
        return self.symmetric_system(bytes_to_hex(sym_key)).decipher(ciphered)


class PgpXor(Pgp):
    name: ClassVar[str] = "pgp-xor"
    symmetric: ClassVar[type[SymmetricSystem]] = Xor

    # As long as the message when RSA can carry it: the XOR key is then a one-time pad.
    # With PKCS#7 the key (the block) has at most 255 bytes, the padding is counted on one byte.
    def random_key_size(self, message_size: int) -> int:
        room: int = self.rsa.max_message_size()
        if self.padding is not None and not self.block:
            room = min(room, 255)
        if room < 1 or (self.block and message_size > room):
            raise MyPgpError(f"RSA key too small to carry a random XOR key of {message_size} bytes")
        return max(1, min(message_size, room))


class PgpAes(Pgp):
    name: ClassVar[str] = "pgp-aes"
    symmetric: ClassVar[type[SymmetricSystem]] = Aes
    KEY_SIZES: ClassVar[tuple[int, ...]] = (32, 24, 16)

    # The longest AES key that RSA can carry
    def random_key_size(self, message_size: int) -> int:
        room: int = self.rsa.max_message_size()
        for size in self.KEY_SIZES:
            if size <= room:
                return size
        raise MyPgpError(f"RSA key too small to carry a random AES key: {max(0, room)} bytes, 16 needed")
