"""ElGamal: second asymmetric cryptosystem.

  -g P X       keys from a safe prime P (= 2Q + 1) and a private key X
  -g -r [BITS] keys from a random safe prime and a random private key
  keys         public Y-G-P, private X-G-P (little-endian hex), Y = G^X mod P
  -c / -d      any input, ciphered as is: one "C1-C2" line per chunk of P's size - 2 bytes
"""
from __future__ import annotations

import os
import unittest

from errors import MyPgpError
from systems.elgamal import ElGamal, ElGamalKey
from tests.helpers import SAFE_PRIME, SMALL_SAFE_PRIME, elgamal_generator_oracle, is_probable_prime, le_hex, le_int


def keys_of(output: bytes) -> tuple[str, str]:
    public, private = (line.split(": ", 1)[1] for line in output.decode().splitlines())
    return public, private


def make_keys(p: int, x: int) -> tuple[str, str]:
    return keys_of(ElGamal(None, False).generate(le_hex(p), le_hex(x)))


class TestFixtures(unittest.TestCase):
    def test_safe_primes(self) -> None:
        for p in (SMALL_SAFE_PRIME, SAFE_PRIME):
            with self.subTest(p=p):
                self.assertTrue(is_probable_prime(p))
                self.assertTrue(is_probable_prime((p - 1) // 2))


class TestKeyGeneration(unittest.TestCase):
    def test_small_example(self) -> None:
        # 65543 = 0x010007, little-endian "070001"; 2 is a square mod 65543, y = 2^1234 mod p
        output: bytes = ElGamal(None, False).generate("070001", le_hex(1234))
        y: int = pow(2, 1234, SMALL_SAFE_PRIME)
        self.assertEqual(output, f"public key: {le_hex(y)}-02-070001\nprivate key: d204-02-070001\n".encode())

    def test_generator_is_a_square_of_order_q(self) -> None:
        for p in (SMALL_SAFE_PRIME, SAFE_PRIME):
            g: int = ElGamal.find_generator(p)
            with self.subTest(p=p):
                self.assertEqual(g, elgamal_generator_oracle(p))
                self.assertEqual(pow(g, (p - 1) // 2, p), 1)
                self.assertNotEqual(g, 1)
        self.assertGreater(ElGamal.find_generator(SAFE_PRIME), 2)

    def test_public_value_matches_pow(self) -> None:
        x: int = 0x123456789ABCDEF
        public, private = make_keys(SAFE_PRIME, x)
        g: int = elgamal_generator_oracle(SAFE_PRIME)
        self.assertEqual(public, f"{le_hex(pow(g, x, SAFE_PRIME))}-{le_hex(g)}-{le_hex(SAFE_PRIME)}")
        self.assertEqual(private, f"{le_hex(x)}-{le_hex(g)}-{le_hex(SAFE_PRIME)}")

    def test_invalid_numbers(self) -> None:
        q: int = (SMALL_SAFE_PRIME - 1) // 2
        for p, x in ((65521, 5), (SMALL_SAFE_PRIME, 0), (SMALL_SAFE_PRIME, q), (SMALL_SAFE_PRIME, SMALL_SAFE_PRIME)):
            with self.subTest(p=p, x=x), self.assertRaises(MyPgpError):
                ElGamal(None, False).generate(le_hex(p), le_hex(x))
        with self.assertRaises(MyPgpError):
            ElGamal(None, False).generate("zz", "01")

    def test_not_a_safe_prime(self) -> None:
        # Composite: no small g has g^((p - 1) / 2) = 1
        with self.assertRaises(MyPgpError):
            ElGamal.find_generator(1000003 * 3)

    def test_random_keys(self) -> None:
        public, private = keys_of(ElGamal(None, False).generate_random(64))
        y, g, p = (le_int(part) for part in public.split("-"))
        x, g2, p2 = (le_int(part) for part in private.split("-"))
        self.assertEqual((g, p), (g2, p2))
        self.assertEqual(p.bit_length(), 64)
        self.assertTrue(is_probable_prime(p) and is_probable_prime((p - 1) // 2))
        self.assertEqual(pow(g, x, p), y)

    def test_random_size_limits(self) -> None:
        with self.assertRaises(MyPgpError):
            ElGamal(None, False).generate_random(16)


class TestKey(unittest.TestCase):
    def test_parse(self) -> None:
        key: ElGamalKey = ElGamalKey.parse("d204-02-070001")
        self.assertEqual((key.value, key.generator, key.prime), (1234, 2, SMALL_SAFE_PRIME))
        self.assertEqual(str(key), "d204-02-070001")
        self.assertEqual(key.chunk_size(), 1)

    def test_parse_rejects(self) -> None:
        for text in ("", "d204-070001", "d204-02-070001-01", "d204-02-ffff", "d204-01-070001", "d204-070001-070001", "zz-02-070001"):
            with self.subTest(text=text), self.assertRaises(MyPgpError):
                ElGamalKey.parse(text)


class TestCipher(unittest.TestCase):
    def setUp(self) -> None:
        self.public, self.private = make_keys(SAFE_PRIME, 0xC0FFEE)

    def round_trip(self, message: bytes) -> bytes:
        ciphered: bytes = ElGamal(self.public, False).cipher(message)
        return ElGamal(self.private, False).decipher(ciphered)

    def test_round_trip_is_exact(self) -> None:
        messages: tuple[bytes, ...] = (
            b"", b"a", b"hello\n", b"no newline", b"\x00", b"ends with zeros\x00\x00\n",
            bytes(30), bytes(31), b"multi\nline\n\nfile\n", os.urandom(1000),
        )
        for message in messages:
            with self.subTest(message=message[:12]):
                self.assertEqual(self.round_trip(message), message)

    def test_one_pair_per_chunk(self) -> None:
        chunk: int = 32 - 2
        for length, pairs in ((0, 0), (1, 1), (chunk, 1), (chunk + 1, 2), (10 * chunk, 10)):
            ciphered: bytes = ElGamal(self.public, False).cipher(bytes(length))
            with self.subTest(length=length):
                self.assertEqual(len(ciphered.splitlines()), pairs)

    def test_pair_decrypts_with_pow(self) -> None:
        ciphered: bytes = ElGamal(self.public, False).cipher(b"Winter")
        c1, c2 = (le_int(part) for part in ciphered.decode().strip().split("-"))
        shared: int = pow(c1, 0xC0FFEE, SAFE_PRIME)
        m: int = c2 * pow(shared, -1, SAFE_PRIME) % SAFE_PRIME
        self.assertEqual(le_hex(m), (b"Winter\x01").hex())

    def test_cipher_is_randomized(self) -> None:
        elgamal = ElGamal(self.public, False)
        self.assertNotEqual(elgamal.cipher(b"same"), elgamal.cipher(b"same"))

    def test_small_prime_one_byte_per_pair(self) -> None:
        public, private = make_keys(SMALL_SAFE_PRIME, 1234)
        ciphered: bytes = ElGamal(public, False).cipher(b"WF\n")
        self.assertEqual(len(ciphered.splitlines()), 3)
        self.assertEqual(ElGamal(private, False).decipher(ciphered), b"WF\n")

    def test_wrong_key(self) -> None:
        ciphered: bytes = ElGamal(self.public, False).cipher(b"secret message " * 10)
        _, other_private = make_keys(SAFE_PRIME, 0xBAD)
        with self.assertRaises(MyPgpError):
            ElGamal(other_private, False).decipher(ciphered)

    def test_invalid_ciphered_input(self) -> None:
        p: str = le_hex(SAFE_PRIME)
        for ciphered in (b"0102", b"01-02-03", b"zz-01", b"00-01", b"01-00", f"{p}-01".encode(), "é".encode()):
            with self.subTest(ciphered=ciphered[:10]), self.assertRaises(MyPgpError):
                ElGamal(self.private, False).decipher(ciphered)

    def test_whitespace_between_pairs_is_ignored(self) -> None:
        ciphered: bytes = ElGamal(self.public, False).cipher(b"x" * 100)
        spaced: bytes = b"  " + ciphered.replace(b"\n", b"\r\n  \n") + b"\n\n"
        self.assertEqual(ElGamal(self.private, False).decipher(spaced), b"x" * 100)

    def test_missing_key(self) -> None:
        with self.assertRaises(MyPgpError):
            ElGamal(None, False).cipher(b"hello")


if __name__ == "__main__":
    unittest.main()
