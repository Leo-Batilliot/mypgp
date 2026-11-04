from __future__ import annotations

import hashlib
import os
import unittest

from sha256 import H0, K, icbrt, pad_message, sha256


class TestConstants(unittest.TestCase):
    def test_first_and_last_constants_match_fips_180_4(self) -> None:
        self.assertEqual(H0[0], 0x6A09E667)
        self.assertEqual(H0[7], 0x5BE0CD19)
        self.assertEqual(K[0], 0x428A2F98)
        self.assertEqual(K[63], 0xC67178F2)
        self.assertEqual((len(H0), len(K)), (8, 64))

    def test_integer_cube_root(self) -> None:
        for n in (1, 7, 8, 9, 26, 27, 28, 10**30, 10**30 - 1, 2**200 + 12345):
            with self.subTest(n=n):
                r: int = icbrt(n)
                self.assertTrue(r ** 3 <= n < (r + 1) ** 3)


class TestPadding(unittest.TestCase):
    def test_padded_length_is_a_multiple_of_64(self) -> None:
        for length in (0, 1, 55, 56, 63, 64, 65, 119, 120):
            with self.subTest(length=length):
                padded: bytes = pad_message(bytes(length))
                self.assertEqual(len(padded) % 64, 0)
                self.assertEqual(padded[length], 0x80)
                self.assertEqual(int.from_bytes(padded[-8:], "big"), length * 8)


class TestDigest(unittest.TestCase):
    def test_fips_180_vectors(self) -> None:
        vectors: tuple[tuple[bytes, str], ...] = (
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        )
        for data, digest in vectors:
            with self.subTest(data=data):
                self.assertEqual(sha256(data).hex(), digest)

    def test_matches_hashlib_around_block_boundaries(self) -> None:
        for length in (1, 54, 55, 56, 57, 63, 64, 65, 127, 128, 129, 1000, 10000):
            data: bytes = os.urandom(length)
            with self.subTest(length=length):
                self.assertEqual(sha256(data), hashlib.sha256(data).digest())


if __name__ == "__main__":
    unittest.main()
