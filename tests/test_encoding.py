from __future__ import annotations

import unittest

from encoding import (
    bytes_to_hex,
    bytes_to_int,
    hex_to_bytes,
    hex_to_int,
    int_to_bytes,
    int_to_hex,
    read_hex,
    reverse,
    reverse_words,
)
from errors import MyPgpError


class TestHexBytes(unittest.TestCase):
    def test_hex_to_bytes(self) -> None:
        self.assertEqual(hex_to_bytes("6b6579"), b"key")
        self.assertEqual(hex_to_bytes("00FF"), b"\x00\xff")

    def test_empty_is_the_empty_byte_string(self) -> None:
        for text in ("", " ", "\n", "\t \r\n"):
            with self.subTest(text=text):
                self.assertEqual(hex_to_bytes(text), b"")

    def test_whitespace_around_and_between_bytes_is_ignored(self) -> None:
        for text in (" 6b6579", "6b6579\n", "\t6b6579 \r\n", "6b 65 79", "6b\n65\t79"):
            with self.subTest(text=text):
                self.assertEqual(hex_to_bytes(text), b"key")

    def test_hex_to_bytes_rejects_invalid(self) -> None:
        for text in ("a", "abc", "zz", "0x", "0x10", "6 b", "-1", "é1", "1g"):
            with self.subTest(text=text), self.assertRaises(MyPgpError):
                hex_to_bytes(text)

    def test_bytes_to_hex_is_lowercase(self) -> None:
        self.assertEqual(bytes_to_hex(b"\xab\xcd"), "abcd")

    def test_round_trip(self) -> None:
        data: bytes = bytes(range(256))
        self.assertEqual(hex_to_bytes(bytes_to_hex(data)), data)


class TestLittleEndianIntegers(unittest.TestCase):
    def test_hex_to_int_is_little_endian(self) -> None:
        self.assertEqual(hex_to_int("01"), 1)
        self.assertEqual(hex_to_int("0100"), 1)
        self.assertEqual(hex_to_int("0001"), 256)
        self.assertEqual(hex_to_int("d3"), 211)
        self.assertEqual(hex_to_int("010001"), 65537)
        self.assertEqual(hex_to_int(""), 0)

    def test_int_to_hex_is_minimal_little_endian(self) -> None:
        self.assertEqual(int_to_hex(0), "00")
        self.assertEqual(int_to_hex(1), "01")
        self.assertEqual(int_to_hex(256), "0001")
        self.assertEqual(int_to_hex(65537), "010001")

    def test_int_round_trip(self) -> None:
        for value in (0, 1, 255, 256, 65537, 2**127 + 3, 2**512 - 1):
            with self.subTest(value=value):
                self.assertEqual(hex_to_int(int_to_hex(value)), value)

    def test_int_to_bytes_drops_trailing_zero_bytes(self) -> None:
        self.assertEqual(int_to_bytes(bytes_to_int(b"ab\x00\x00")), b"ab")

    def test_int_to_bytes_zero(self) -> None:
        self.assertEqual(int_to_bytes(0), b"\x00")

    def test_int_to_bytes_rejects_negative(self) -> None:
        with self.assertRaises(MyPgpError):
            int_to_bytes(-1)

    def test_bytes_to_int(self) -> None:
        self.assertEqual(bytes_to_int(b"\x01\x02"), 0x0201)
        self.assertEqual(bytes_to_int(b""), 0)


class TestReverse(unittest.TestCase):
    def test_reverse(self) -> None:
        self.assertEqual(reverse(b"abc"), b"cba")
        self.assertEqual(reverse(b""), b"")

    def test_reverse_words(self) -> None:
        self.assertEqual(
            reverse_words(bytes(range(8))), bytes([3, 2, 1, 0, 7, 6, 5, 4])
        )

    def test_reverse_words_is_an_involution(self) -> None:
        data: bytes = bytes(range(32))
        self.assertEqual(reverse_words(reverse_words(data)), data)

    def test_reverse_words_custom_size(self) -> None:
        self.assertEqual(reverse_words(b"abcdef", 2), b"badcfe")

    def test_reverse_words_rejects_bad_length(self) -> None:
        with self.assertRaises(MyPgpError):
            reverse_words(b"abcde")

    def test_reverse_words_rejects_bad_size(self) -> None:
        for size in (0, -4):
            with self.subTest(size=size), self.assertRaises(MyPgpError):
                reverse_words(b"abcd", size)


class TestReadHex(unittest.TestCase):
    def test_strips_whitespace(self) -> None:
        for data in (b"6b6579\n", b"6b6579 \r\n", b"  6b6579", b"6b65 79", b"6b\n65\n79\n"):
            with self.subTest(data=data):
                self.assertEqual(read_hex(data), b"key")

    def test_empty_input(self) -> None:
        self.assertEqual(read_hex(b""), b"")
        self.assertEqual(read_hex(b"\n"), b"")

    def test_rejects_non_ascii(self) -> None:
        with self.assertRaises(MyPgpError):
            read_hex("é".encode())

    def test_rejects_invalid_hex(self) -> None:
        for data in (b"xyz\n", b"6b6\n", b"6 b\n", b"\x006b"):
            with self.subTest(data=data), self.assertRaises(MyPgpError):
                read_hex(data)


if __name__ == "__main__":
    unittest.main()
