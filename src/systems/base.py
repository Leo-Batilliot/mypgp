from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from encoding import bytes_to_hex, hex_to_bytes, read_hex
from errors import MyPgpError
from mac import TAG_SIZE, constant_time_equal, derive_key, hmac_sha256
from modes import cbc_decrypt, cbc_encrypt, ctr_crypt, new_iv
from padding import pkcs7_pad, pkcs7_unpad

MAC_LABEL: bytes = b"my_pgp authentication key"


class CryptoSystem(ABC):
    name: ClassVar[str]
    # A single trailing line feed on stdin (echo) is not part of the message
    strips_newline: ClassVar[bool] = True

    # padding: None, or the scheme asked with -p ("oaep" or "pkcs1"; symmetric systems use PKCS#7)
    # signed: -s, the key then also holds the signer's RSA key
    def __init__(self, key: str | None, block: bool, padding: str | None = None, signed: bool = False) -> None:
        self.key: str | None = key
        self.block: bool = block
        self.padding: str | None = padding
        self.signed: bool = signed

    # Called before stdin is read: a key that is going to be rejected must not
    # wait for an input that may never be closed.
    def check_key(self, mode: str) -> None:
        pass

    @abstractmethod
    def cipher(self, message: bytes) -> bytes:
        ...

    @abstractmethod
    def decipher(self, ciphered: bytes) -> bytes:
        ...


class SymmetricSystem(CryptoSystem, ABC):
    # operation: -m, how the stream mode chains the blocks ("ecb", the subject's, "cbc" or "ctr")
    # authenticated: -a, an HMAC-SHA256 tag follows the ciphered message
    def __init__(
        self, key: str | None, block: bool, padding: str | None = None, signed: bool = False,
        operation: str = "ecb", authenticated: bool = False,
    ) -> None:
        super().__init__(key, block, padding, signed)
        if padding is not None and block:
            raise MyPgpError("-p can't be used with -b: a single block is never padded")
        self.operation: str = operation
        self.authenticated: bool = authenticated

    @abstractmethod
    def block_size(self) -> int:
        ...

    @abstractmethod
    def cipher_block(self, block: bytes) -> bytes:
        ...

    @abstractmethod
    def decipher_block(self, block: bytes) -> bytes:
        ...

    def check_key(self, mode: str) -> None:
        if self.padding is not None and self.block_size() > 255:
            raise MyPgpError(f"PKCS#7 padding needs a block of at most 255 bytes, not {self.block_size()}")

    def cipher(self, message: bytes) -> bytes:
        if self.block:
            self.check_block(message, "message")
            return (bytes_to_hex(self.cipher_block(message)) + "\n").encode()
        ciphered: bytes = self.cipher_message(message)
        if self.authenticated:
            ciphered += hmac_sha256(self.mac_key(), ciphered)
        return (bytes_to_hex(ciphered) + "\n").encode()

    def decipher(self, ciphered: bytes) -> bytes:
        data: bytes = read_hex(ciphered)
        if self.block:
            self.check_block(data, "ciphered message")
            return self.decipher_block(data) + b"\n"
        if self.authenticated:
            data = self.check_tag(data)
        return self.decipher_message(data) + b"\n"

    # Stream mode. ECB (the subject's): each block on its own. CBC and CTR: the random
    # IV (or first counter) comes first, the receiver needs it to decipher.
    def cipher_message(self, message: bytes) -> bytes:
        if self.operation == "cbc":
            iv: bytes = new_iv(self.block_size())
            return iv + cbc_encrypt(self.cipher_block, iv, self.pad(message))
        if self.operation == "ctr":
            counter: bytes = new_iv(self.block_size())
            return counter + ctr_crypt(self.cipher_block, counter, message)
        return self.cipher_stream(message)

    def decipher_message(self, data: bytes) -> bytes:
        if self.operation == "ecb":
            return self.decipher_ecb(data)
        size: int = self.block_size()
        if len(data) < size:
            raise MyPgpError(f"ciphered message is too short: it starts with a {size}-byte IV")
        iv, body = data[:size], data[size:]
        if self.operation == "ctr":
            return ctr_crypt(self.cipher_block, iv, body)
        self.check_whole_blocks(body)
        deciphered: bytes = cbc_decrypt(self.decipher_block, iv, body)
        return deciphered if self.padding is None else pkcs7_unpad(deciphered, size)

    def decipher_ecb(self, data: bytes) -> bytes:
        if self.padding is None:
            return self.decipher_stream(data)
        self.check_whole_blocks(data)
        return pkcs7_unpad(self.decipher_stream(data), self.block_size())

    def cipher_stream(self, message: bytes) -> bytes:
        return b"".join(self.cipher_block(block) for block in self.split_blocks(self.pad(message)))

    # Without -p, the 00 padding added on cipher is part of the deciphered output
    def decipher_stream(self, ciphered: bytes) -> bytes:
        return b"".join(self.decipher_block(block) for block in self.split_blocks(self.zero_pad(ciphered)))

    def split_blocks(self, data: bytes) -> list[bytes]:
        size: int = self.block_size()
        return [data[i:i + size] for i in range(0, len(data), size)]

    # With -p, PKCS#7; otherwise the subject's padding: 00 bytes up to the block size
    def pad(self, data: bytes) -> bytes:
        if self.padding is None:
            return self.zero_pad(data)
        return pkcs7_pad(data, self.block_size())

    # Last block padded with 00 up to the block size, on cipher and decipher alike
    def zero_pad(self, data: bytes) -> bytes:
        return data + bytes(-len(data) % self.block_size())

    def check_block(self, block: bytes, what: str) -> None:
        if len(block) != self.block_size():
            raise MyPgpError(
                f"{what} is {len(block)} bytes long but block mode needs {self.block_size()} bytes"
            )

    def check_whole_blocks(self, data: bytes) -> None:
        if len(data) % self.block_size() != 0:
            raise MyPgpError(f"ciphered message is not made of {self.block_size()}-byte blocks")

    # -a: the tag key is derived from the symmetric key (its bytes, not how its hex is written)
    def mac_key(self) -> bytes:
        if self.key is None:
            raise MyPgpError("missing key")
        return derive_key(hex_to_bytes(self.key), MAC_LABEL)

    # Encrypt-then-MAC: the tag covers everything before it, and is checked before
    # anything is deciphered
    def check_tag(self, data: bytes) -> bytes:
        if len(data) < TAG_SIZE:
            raise MyPgpError(f"ciphered message is too short: it ends with a {TAG_SIZE}-byte tag")
        body, tag = data[:-TAG_SIZE], data[-TAG_SIZE:]
        if not constant_time_equal(hmac_sha256(self.mac_key(), body), tag):
            raise MyPgpError("invalid tag: the ciphered message was modified, or the key is wrong")
        return body


class AsymmetricSystem(CryptoSystem, ABC):
    @abstractmethod
    def generate(self, first: str, second: str) -> bytes:
        ...

    # -g -r [BITS]: keys from random numbers instead of the ones given on the command line
    @abstractmethod
    def generate_random(self, bits: int | None) -> bytes:
        ...
