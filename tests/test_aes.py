"""AES system with the Epitech convention (4-byte words read little-endian)."""
from __future__ import annotations

import os
import unittest

from errors import MyPgpError
from systems.aes import Aes
from tests.helpers import FIPS_PLAINTEXT, FIPS_VECTORS, word_reverse

KEY_HEX: str = FIPS_VECTORS[128][0]


def epitech_vector(bits: int) -> tuple[str, bytes, str]:
    """Translate a FIPS vector into the Epitech convention.

    The key words are given reversed on the command line, and every word of
    the ciphered block is printed reversed.
    """
    key_hex, ciphered_hex = FIPS_VECTORS[bits]
    return (
        word_reverse(bytes.fromhex(key_hex)).hex(),
        bytes.fromhex(FIPS_PLAINTEXT),
        word_reverse(bytes.fromhex(ciphered_hex)).hex(),
    )


class TestAesKey(unittest.TestCase):
    def test_missing_key(self) -> None:
        with self.assertRaises(MyPgpError):
            Aes(None, False)

    def test_invalid_key_length(self) -> None:
        for size in (1, 8, 15, 17, 20, 31, 33, 64):
            with self.subTest(size=size), self.assertRaises(MyPgpError):
                Aes("00" * size, False)

    def test_invalid_key_hex(self) -> None:
        for key in ("", "zz" * 16, "0" * 31):
            with self.subTest(key=key), self.assertRaises(MyPgpError):
                Aes(key, False)

    def test_valid_key_lengths(self) -> None:
        for size in (16, 24, 32):
            with self.subTest(size=size):
                self.assertEqual(Aes("00" * size, False).block_size(), 16)


class TestAesBlock(unittest.TestCase):
    def test_cipher_epitech_vectors(self) -> None:
        for bits in FIPS_VECTORS:
            key, message, expected = epitech_vector(bits)
            with self.subTest(bits=bits):
                self.assertEqual(Aes(key, True).cipher(message), (expected + "\n").encode())

    def test_decipher_epitech_vectors(self) -> None:
        for bits in FIPS_VECTORS:
            key, message, ciphered = epitech_vector(bits)
            with self.subTest(bits=bits):
                self.assertEqual(Aes(key, True).decipher((ciphered + "\n").encode()), message + b"\n")

    def test_round_trip(self) -> None:
        for size in (16, 24, 32):
            for _ in range(5):
                key, block = os.urandom(size).hex(), os.urandom(16)
                aes = Aes(key, True)
                with self.subTest(key=key, block=block.hex()):
                    self.assertEqual(aes.decipher(aes.cipher(block)), block + b"\n")

    def test_cipher_rejects_wrong_size(self) -> None:
        aes = Aes(KEY_HEX, True)
        for message in (b"", b"short", bytes(17), bytes(32)):
            with self.subTest(size=len(message)), self.assertRaises(MyPgpError):
                aes.cipher(message)

    def test_decipher_rejects_wrong_size(self) -> None:
        aes = Aes(KEY_HEX, True)
        for ciphered in (b"00" * 15, b"00" * 32):
            with self.subTest(size=len(ciphered)), self.assertRaises(MyPgpError):
                aes.decipher(ciphered + b"\n")


class TestAesStream(unittest.TestCase):
    def setUp(self) -> None:
        self.aes = Aes(KEY_HEX, False)
        self.block = Aes(KEY_HEX, True)

    def test_each_block_is_ciphered_independently(self) -> None:
        """Stream mode is ECB: output = concatenation of the ciphered 16-byte blocks."""
        first, second = b"A" * 16, b"B" * 16
        expected: bytes = self.block.cipher(first).strip() + self.block.cipher(second).strip()
        self.assertEqual(self.aes.cipher(first + second), expected + b"\n")

    def test_identical_blocks_give_identical_output(self) -> None:
        ciphered: bytes = self.aes.cipher(b"X" * 32).strip()
        self.assertEqual(ciphered[:32], ciphered[32:])

    def test_last_block_is_zero_padded(self) -> None:
        message: bytes = b"hello"
        expected: bytes = self.block.cipher(message + bytes(11))
        self.assertEqual(self.aes.cipher(message), expected)

    def test_output_length_is_multiple_of_block(self) -> None:
        for size in (1, 15, 16, 17, 100):
            with self.subTest(size=size):
                hex_len: int = len(self.aes.cipher(b"x" * size).strip())
                self.assertEqual(hex_len % 32, 0)
                self.assertEqual(hex_len, 32 * -(-size // 16))

    def test_round_trip(self) -> None:
        messages: tuple[bytes, ...] = (
            b"a",
            b"exactly 16 bytes",
            b"hello world, this is longer than a block",
            b"multi\nline\n",
            os.urandom(500).replace(b"\x00", b"\x01"),
        )
        for size in (16, 24, 32):
            aes = Aes(os.urandom(size).hex(), False)
            for message in messages:
                with self.subTest(size=size, message=message[:20]):
                    padded: bytes = message + bytes(-len(message) % 16)
                    self.assertEqual(aes.decipher(aes.cipher(message)), padded + b"\n")

    def test_empty(self) -> None:
        self.assertEqual(self.aes.cipher(b""), b"\n")
        for ciphered in (b"", b"\n", b" \n"):
            with self.subTest(ciphered=ciphered):
                self.assertEqual(self.aes.decipher(ciphered), b"\n")

    def test_padding_is_kept_on_decipher(self) -> None:
        self.assertEqual(self.aes.decipher(self.aes.cipher(b"ab")), b"ab" + bytes(14) + b"\n")

    def test_decipher_pads_partial_block_with_zeros(self) -> None:
        self.assertEqual(self.aes.decipher(b"00" * 20 + b"\n"), self.aes.decipher(b"00" * 32 + b"\n"))
        self.assertEqual(len(self.aes.decipher(b"00" * 20 + b"\n")), 33)

    def test_decipher_rejects_invalid_hex(self) -> None:
        with self.assertRaises(MyPgpError):
            self.aes.decipher(b"not hexadecimal at all!!\n")


if __name__ == "__main__":
    unittest.main()
