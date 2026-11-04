from __future__ import annotations

import os
import unittest

from errors import MyPgpError
from systems.base import SymmetricSystem
from systems.xor import Xor
from tests.helpers import xor_block_oracle, xor_stream_oracle

KEY_HEX: str = "6b6579"  # "key"
KEY: bytes = bytes.fromhex(KEY_HEX)


class TestXorKey(unittest.TestCase):
    def test_missing_key(self) -> None:
        with self.assertRaises(MyPgpError):
            Xor(None, False)

    def test_invalid_key(self) -> None:
        for key in ("", " ", "6", "zz", "6b6 579", "0x6b"):
            with self.subTest(key=key), self.assertRaises(MyPgpError):
                Xor(key, False)

    def test_key_whitespace_is_ignored(self) -> None:
        for key in (" 6b6579", "6b6579\n", "6b65 79", "6B6579"):
            with self.subTest(key=key):
                self.assertEqual(Xor(key, True).cipher(b"abc"), b"080718\n")

    def test_block_size_is_key_size(self) -> None:
        self.assertEqual(Xor(KEY_HEX, False).block_size(), 3)
        self.assertEqual(Xor("00" * 32, False).block_size(), 32)


class TestXorBlock(unittest.TestCase):
    def setUp(self) -> None:
        self.xor = Xor(KEY_HEX, True)

    def test_cipher_known_value(self) -> None:
        # "cba" ^ "key" -> 08 07 18
        self.assertEqual(self.xor.cipher(b"abc"), b"080718\n")

    def test_cipher_matches_oracle(self) -> None:
        for _ in range(20):
            key, message = os.urandom(16), os.urandom(16)
            with self.subTest(key=key.hex(), message=message.hex()):
                expected: str = xor_block_oracle(message, key).hex() + "\n"
                self.assertEqual(Xor(key.hex(), True).cipher(message), expected.encode())

    def test_decipher_known_value(self) -> None:
        self.assertEqual(self.xor.decipher(b"080718\n"), b"abc\n")

    def test_round_trip(self) -> None:
        for _ in range(20):
            key, message = os.urandom(8), os.urandom(8)
            xor = Xor(key.hex(), True)
            with self.subTest(key=key.hex(), message=message.hex()):
                self.assertEqual(xor.decipher(xor.cipher(message)), message + b"\n")

    def test_cipher_rejects_wrong_size(self) -> None:
        for message in (b"", b"ab", b"abcd"):
            with self.subTest(message=message), self.assertRaises(MyPgpError):
                self.xor.cipher(message)

    def test_decipher_rejects_wrong_size(self) -> None:
        for ciphered in (b"0807\n", b"08071800\n"):
            with self.subTest(ciphered=ciphered), self.assertRaises(MyPgpError):
                self.xor.decipher(ciphered)

    def test_decipher_rejects_invalid_hex(self) -> None:
        with self.assertRaises(MyPgpError):
            self.xor.decipher(b"zzzzzz\n")


class TestXorStream(unittest.TestCase):
    def setUp(self) -> None:
        self.xor = Xor(KEY_HEX, False)

    def test_cipher_matches_oracle(self) -> None:
        message: bytes = b"I love spinach\n"
        expected: str = xor_stream_oracle(message, KEY).hex() + "\n"
        self.assertEqual(self.xor.cipher(message), expected.encode())

    def test_cipher_pads_last_block_with_zeros(self) -> None:
        # "abcd" -> blocks "abc" and "d\0\0"
        ciphered: bytes = self.xor.cipher(b"abcd")
        self.assertEqual(len(ciphered.strip()), 2 * 6)
        self.assertEqual(ciphered.strip()[6:], xor_block_oracle(b"d\x00\x00", KEY).hex().encode())

    def test_cipher_empty_message(self) -> None:
        self.assertEqual(self.xor.cipher(b""), b"\n")

    def test_decipher_keeps_padding_and_adds_newline(self) -> None:
        self.assertEqual(self.xor.decipher(self.xor.cipher(b"abcd")), b"abcd\x00\x00\n")

    def test_decipher_empty_input(self) -> None:
        for ciphered in (b"", b"\n", b"  \n"):
            with self.subTest(ciphered=ciphered):
                self.assertEqual(self.xor.decipher(ciphered), b"\n")

    def test_round_trip_text_and_binary(self) -> None:
        messages: tuple[bytes, ...] = (
            b"a",
            b"Hello, World!",
            b"multi\nline\nmessage\n",
            "accents: éàù".encode(),
            os.urandom(1000).replace(b"\x00", b"\x01"),
        )
        for message in messages:
            with self.subTest(message=message[:20]):
                padded: bytes = message + bytes(-len(message) % len(KEY))
                self.assertEqual(self.xor.decipher(self.xor.cipher(message)), padded + b"\n")

    def test_stream_matches_block_by_block(self) -> None:
        """Xor ciphers the whole stream at once: same result as one block at a time."""
        for key in ("41", KEY_HEX, "00ff", os.urandom(26).hex(), os.urandom(300).hex()):
            xor: Xor = Xor(key, False)
            for length in (0, 1, 2, 3, 25, 26, 27, 1000):
                data: bytes = os.urandom(length)
                with self.subTest(key=key[:8], length=length):
                    self.assertEqual(xor.cipher_stream(data), SymmetricSystem.cipher_stream(xor, data))
                    self.assertEqual(xor.decipher_stream(data), SymmetricSystem.decipher_stream(xor, data))

    def test_decipher_pads_partial_block_with_zeros(self) -> None:
        # "08071800" -> blocks "080718" and "00" padded to "000000", which XOR "key" gives "yek"
        self.assertEqual(self.xor.decipher(b"08071800\n"), b"abcyek\n")

    def test_decipher_hex_whitespace_is_ignored(self) -> None:
        for ciphered in (b"080718\n", b" 080718 \n", b"0807 18\n", b"0807\n18\n", b"080718"):
            with self.subTest(ciphered=ciphered):
                self.assertEqual(self.xor.decipher(ciphered), b"abc\n")

    def test_decipher_rejects_invalid_hex(self) -> None:
        for ciphered in (b"xyz\n", b"080", b"0 80718\n", "é".encode()):
            with self.subTest(ciphered=ciphered), self.assertRaises(MyPgpError):
                self.xor.decipher(ciphered)


if __name__ == "__main__":
    unittest.main()
