from __future__ import annotations

from typing import ClassVar

from aes_core import AesCore
from encoding import hex_to_bytes, reverse_words
from errors import MyPgpError
from systems.base import SymmetricSystem


class Aes(SymmetricSystem):
    name: ClassVar[str] = "aes"

    def __init__(
        self, key: str | None, block: bool, padding: str | None = None, signed: bool = False,
        operation: str = "ecb", authenticated: bool = False,
    ) -> None:
        super().__init__(key, block, padding, signed, operation, authenticated)
        if key is None:
            raise MyPgpError("missing key")
        key_bytes: bytes = hex_to_bytes(key)
        if len(key_bytes) not in (16, 24, 32):
            raise MyPgpError(f"invalid AES key: {len(key_bytes)} bytes (expected 16, 24 or 32)")
        self.core: AesCore = AesCore(reverse_words(key_bytes))

    def block_size(self) -> int:
        return 16

    def cipher_block(self, block: bytes) -> bytes:
        return reverse_words(self.core.encrypt_block(block))

    def decipher_block(self, block: bytes) -> bytes:
        return self.core.decrypt_block(reverse_words(block))
