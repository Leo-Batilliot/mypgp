from __future__ import annotations

from typing import ClassVar

from encoding import hex_to_bytes, reverse, reverse_words
from errors import MyPgpError
from systems.base import SymmetricSystem


class Xor(SymmetricSystem):
    name: ClassVar[str] = "xor"

    def __init__(
        self, key: str | None, block: bool, padding: str | None = None, signed: bool = False,
        operation: str = "ecb", authenticated: bool = False,
    ) -> None:
        super().__init__(key, block, padding, signed, operation, authenticated)
        if key is None:
            raise MyPgpError("missing key")
        self.key_bytes: bytes = reverse(hex_to_bytes(key))
        if not self.key_bytes:
            raise MyPgpError("the XOR key can't be empty")

    def block_size(self) -> int:
        return len(self.key_bytes)

    def cipher_block(self, block: bytes) -> bytes:
        return reverse(self._xor(block))

    def decipher_block(self, block: bytes) -> bytes:
        return self._xor(reverse(block))

    # Same result as one cipher_block per block, without one bytes object per block:
    # reverse(B ^ key_bytes) == reverse(B) ^ reverse(key_bytes)
    def cipher_stream(self, message: bytes) -> bytes:
        return self._xor_stream(reverse_words(self.pad(message), self.block_size()), reverse(self.key_bytes))

    def decipher_stream(self, ciphered: bytes) -> bytes:
        return self._xor_stream(reverse_words(self.zero_pad(ciphered), self.block_size()), self.key_bytes)

    @staticmethod
    def _xor_stream(data: bytes, key: bytes) -> bytes:
        stream: bytes = key * (len(data) // len(key))
        value: int = int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")
        return value.to_bytes(len(data), "little")

    def _xor(self, data: bytes) -> bytes:
        res: bytearray = bytearray()
        for key, msg in zip(self.key_bytes, data):
            res.append(key ^ msg)
        return bytes(res)
