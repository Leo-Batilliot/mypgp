from __future__ import annotations

import hashlib
import os
import unittest

from errors import MyPgpError
from padding import (
    emsa_encode,
    mgf1,
    oaep_decode,
    oaep_encode,
    pkcs1_decode,
    pkcs1_encode,
    pkcs7_pad,
    pkcs7_unpad,
)


class TestPkcs7(unittest.TestCase):
    def test_pad(self) -> None:
        self.assertEqual(pkcs7_pad(b"abc", 4), b"abc\x01")
        self.assertEqual(pkcs7_pad(b"ab", 4), b"ab\x02\x02")
        self.assertEqual(pkcs7_pad(b"", 3), b"\x03\x03\x03")

    def test_full_block_adds_a_whole_block(self) -> None:
        self.assertEqual(pkcs7_pad(b"abcd", 4), b"abcd\x04\x04\x04\x04")

    def test_round_trip(self) -> None:
        for size in (1, 3, 16, 255):
            for length in (0, 1, size - 1, size, size + 1, 3 * size):
                data: bytes = os.urandom(length)
                with self.subTest(size=size, length=length):
                    padded: bytes = pkcs7_pad(data, size)
                    self.assertEqual(len(padded) % size, 0)
                    self.assertEqual(pkcs7_unpad(padded, size), data)

    def test_message_ending_like_padding_survives(self) -> None:
        for data in (b"ab\x01", b"ab\x00", b"\x02\x02"):
            with self.subTest(data=data):
                self.assertEqual(pkcs7_unpad(pkcs7_pad(data, 4), 4), data)

    def test_block_size_limits(self) -> None:
        for size in (0, 256):
            with self.subTest(size=size), self.assertRaises(MyPgpError):
                pkcs7_pad(b"abc", size)

    def test_invalid_padding(self) -> None:
        for data in (b"", b"abc", b"abc\x00", b"abc\x05", b"ab\x01\x02", b"a\x03\x02\x03"):
            with self.subTest(data=data), self.assertRaises(MyPgpError):
                pkcs7_unpad(data, 4)


class TestOaep(unittest.TestCase):
    SIZE: int = 128

    def test_mgf1_matches_its_definition(self) -> None:
        seed: bytes = b"seed"
        expected: bytes = hashlib.sha256(seed + bytes(4)).digest() + hashlib.sha256(seed + b"\x00\x00\x00\x01").digest()
        self.assertEqual(mgf1(seed, 40), expected[:40])

    def test_encoded_message_layout(self) -> None:
        em: bytes = oaep_encode(b"hello", self.SIZE)
        self.assertEqual(len(em), self.SIZE)
        self.assertEqual(em[0], 0)

    def test_round_trip(self) -> None:
        for length in (0, 1, 16, self.SIZE - 66):
            message: bytes = os.urandom(length)
            with self.subTest(length=length):
                self.assertEqual(oaep_decode(oaep_encode(message, self.SIZE), self.SIZE), message)

    def test_encoding_is_randomized(self) -> None:
        self.assertNotEqual(oaep_encode(b"hello", self.SIZE), oaep_encode(b"hello", self.SIZE))

    def test_message_too_long(self) -> None:
        with self.assertRaises(MyPgpError):
            oaep_encode(bytes(self.SIZE - 65), self.SIZE)
        with self.assertRaises(MyPgpError):
            oaep_encode(b"", 65)

    def test_tampered_message_is_rejected(self) -> None:
        em: bytes = oaep_encode(b"hello", self.SIZE)
        for index in (0, 1, 40, self.SIZE - 1):
            tampered: bytes = em[:index] + bytes([em[index] ^ 1]) + em[index + 1:]
            with self.subTest(index=index), self.assertRaises(MyPgpError):
                oaep_decode(tampered, self.SIZE)


class TestPkcs1(unittest.TestCase):
    SIZE: int = 64

    def test_encoded_message_layout(self) -> None:
        em: bytes = pkcs1_encode(b"hello", self.SIZE)
        self.assertEqual(len(em), self.SIZE)
        self.assertEqual(em[:2], b"\x00\x02")
        self.assertNotIn(0, em[2:self.SIZE - 6])
        self.assertEqual(em[-6:], b"\x00hello")

    def test_round_trip(self) -> None:
        for length in (0, 1, 32, self.SIZE - 11):
            message: bytes = os.urandom(length)
            with self.subTest(length=length):
                self.assertEqual(pkcs1_decode(pkcs1_encode(message, self.SIZE), self.SIZE), message)

    def test_message_too_long(self) -> None:
        with self.assertRaises(MyPgpError):
            pkcs1_encode(bytes(self.SIZE - 10), self.SIZE)

    def test_invalid_padding(self) -> None:
        bad: tuple[bytes, ...] = (
            b"\x00\x01" + b"\xff" * 61 + b"\x00",       # signature type, not encryption
            b"\x01\x02" + b"\xff" * 61 + b"\x00",
            b"\x00\x02" + b"\xff" * 62,                  # no separator
            b"\x00\x02" + b"\xff" * 7 + b"\x00" + bytes(54),  # PS shorter than 8 bytes
        )
        for em in bad:
            with self.subTest(em=em[:12]), self.assertRaises(MyPgpError):
                pkcs1_decode(em, self.SIZE)


class TestEmsa(unittest.TestCase):
    def test_layout(self) -> None:
        em: bytes = emsa_encode(b"hello", 64)
        digest_info: bytes = bytes.fromhex("3031300d060960864801650304020105000420")
        self.assertEqual(em, b"\x00\x01" + b"\xff" * 10 + b"\x00" + digest_info + hashlib.sha256(b"hello").digest())

    def test_modulus_too_small(self) -> None:
        emsa_encode(b"", 62)
        with self.assertRaises(MyPgpError):
            emsa_encode(b"", 61)


if __name__ == "__main__":
    unittest.main()
