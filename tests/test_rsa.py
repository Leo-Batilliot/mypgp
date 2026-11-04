from __future__ import annotations

import math
import os
import unittest

from errors import MyPgpError
from systems.rsa import Rsa, RsaKey
from tests.helpers import (
    P,
    P_HEX,
    Q,
    Q_HEX,
    RSA_KEYS,
    SMALL_P_HEX,
    SMALL_Q_HEX,
    is_probable_prime,
    le_hex,
    le_int,
    rsa_oracle,
)


class TestFixtures(unittest.TestCase):
    def test_fixture_numbers_are_prime(self) -> None:
        for n in (P, Q, le_int(SMALL_P_HEX), le_int(SMALL_Q_HEX)):
            with self.subTest(n=n):
                self.assertTrue(is_probable_prime(n))


class TestRsaKey(unittest.TestCase):
    def test_parse(self) -> None:
        key = RsaKey.parse("010001-19bb")
        self.assertEqual(key.exponent, 65537)
        self.assertEqual(key.modulus, 0xBB19)

    def test_str_round_trip(self) -> None:
        self.assertEqual(str(RsaKey.parse(RSA_KEYS.public)), RSA_KEYS.public)
        self.assertEqual(str(RsaKey.parse(RSA_KEYS.private)), RSA_KEYS.private)

    def test_parse_rejects_bad_format(self) -> None:
        for text in ("", "010001", "01-02-03", "010001:19bb", "zz-19bb", "01-1", "0 1-19bb"):
            with self.subTest(text=text), self.assertRaises(MyPgpError):
                RsaKey.parse(text)

    def test_parse_empty_parts_are_zero(self) -> None:
        for text, expected in (("-19bb", (0, 0xBB19)), ("0101-", (0x101, 0)), ("-", (0, 0))):
            key = RsaKey.parse(text)
            with self.subTest(text=text):
                self.assertEqual((key.exponent, key.modulus), expected)

    def test_parse_ignores_whitespace(self) -> None:
        key = RsaKey.parse(" 0101 - 19 bb\n")
        self.assertEqual((key.exponent, key.modulus), (0x101, 0xBB19))

    def test_tiny_modulus(self) -> None:
        self.assertEqual(Rsa("03-01", False).cipher(b"WF"), b"00\n")
        with self.assertRaises(MyPgpError):
            Rsa("03-00", False).cipher(b"WF")

    def test_exponent_zero(self) -> None:
        self.assertEqual(Rsa("-19bb", False).cipher(b"WF"), b"01\n")


class TestKeyGeneration(unittest.TestCase):
    def test_textbook_primes(self) -> None:
        # p=61, q=53: lambda = 780, 65537 is too big so e falls back to 257
        public, private = Rsa.make_keys(61, 53)
        expected = rsa_oracle(61, 53)
        self.assertEqual((public.exponent, public.modulus), (257, 3233))
        self.assertEqual((private.exponent, private.modulus), (expected.d, 3233))

    def test_e_and_d_are_inverses_modulo_carmichael(self) -> None:
        public, private = Rsa.make_keys(P, Q)
        carmichael: int = (P - 1) * (Q - 1) // math.gcd(P - 1, Q - 1)
        self.assertEqual(public.exponent * private.exponent % carmichael, 1)

    def test_random_modulus_always_has_the_requested_size(self) -> None:
        for bits in (16, 17, 64, 255, 256, 512):
            for _ in range(5):
                public, private = Rsa(None, False).generate_random(bits).decode().splitlines()
                e, n = (le_int(part) for part in public.split(": ")[1].split("-"))
                d: int = le_int(private.split(": ")[1].split("-")[0])
                with self.subTest(bits=bits):
                    self.assertEqual(n.bit_length(), bits)
                    self.assertEqual(pow(pow(42, e, n), d, n), 42)

    def test_choose_exponent_prefers_65537(self) -> None:
        self.assertEqual(Rsa.choose_exponent(10**9), 65537)

    def test_choose_exponent_fallbacks(self) -> None:
        self.assertEqual(Rsa.choose_exponent(780), 257)
        self.assertEqual(Rsa.choose_exponent(2 * 257 * 65537 * 100), 17)
        self.assertEqual(Rsa.choose_exponent(4), 3)

    def test_choose_exponent_impossible(self) -> None:
        with self.assertRaises(MyPgpError):
            Rsa.choose_exponent(2)

    def test_generate_output_small_primes(self) -> None:
        expected = rsa_oracle(le_int(SMALL_P_HEX), le_int(SMALL_Q_HEX))
        output: bytes = Rsa(None, False).generate(SMALL_P_HEX, SMALL_Q_HEX)
        self.assertEqual(
            output,
            f"public key: {expected.public}\nprivate key: {expected.private}\n".encode(),
        )

    def test_generate_output_256_bit_primes(self) -> None:
        output: bytes = Rsa(None, False).generate(P_HEX, Q_HEX)
        self.assertEqual(
            output,
            f"public key: {RSA_KEYS.public}\nprivate key: {RSA_KEYS.private}\n".encode(),
        )

    def test_generate_modulus_is_little_endian_product(self) -> None:
        output: str = Rsa(None, False).generate(SMALL_P_HEX, SMALL_Q_HEX).decode()
        self.assertTrue(output.splitlines()[0].endswith("-" + le_hex(211 * 227)))

    def test_generate_equal_primes(self) -> None:
        # lambda(211 * 211) = lcm(210, 210) = 210, so e = 17 and d = 17^-1 mod 210 = 173
        output: bytes = Rsa(None, False).generate("d3", "d3")
        self.assertEqual(output, f"public key: 11-{le_hex(211 * 211)}\nprivate key: ad-{le_hex(211 * 211)}\n".encode())

    def test_generate_ignores_whitespace(self) -> None:
        self.assertEqual(Rsa(None, False).generate(" d3", "e3\n"), Rsa(None, False).generate("d3", "e3"))

    def test_generate_rejects_too_small(self) -> None:
        for p, q in (("00", "d3"), ("01", "d3"), ("d3", "01"), ("", "d3"), ("02", "02"), ("02", "03")):
            with self.subTest(p=p, q=q), self.assertRaises(MyPgpError):
                Rsa(None, False).generate(p, q)

    def test_generate_rejects_invalid_hex(self) -> None:
        for p, q in (("zz", "e3"), ("d3", "xyz"), ("d", "e3"), ("211", "227")):
            with self.subTest(p=p, q=q), self.assertRaises(MyPgpError):
                Rsa(None, False).generate(p, q)


class TestCipherDecipher(unittest.TestCase):
    def setUp(self) -> None:
        self.public = Rsa(RSA_KEYS.public, False)
        self.private = Rsa(RSA_KEYS.private, False)

    def test_cipher_matches_oracle(self) -> None:
        message: bytes = b"hello"
        expected: int = pow(int.from_bytes(message, "little"), RSA_KEYS.e, RSA_KEYS.n)
        self.assertEqual(self.public.cipher(message), (le_hex(expected) + "\n").encode())

    def test_decipher_matches_oracle(self) -> None:
        ciphered: int = pow(int.from_bytes(b"hello", "little"), RSA_KEYS.e, RSA_KEYS.n)
        self.assertEqual(self.private.decipher((le_hex(ciphered) + "\n").encode()), b"hello\n")

    def test_round_trip(self) -> None:
        for message in (b"a", b"hello", b"RSA with 256-bit primes!", os.urandom(40) + b"\x01"):
            with self.subTest(message=message):
                self.assertEqual(
                    self.private.decipher(self.public.cipher(message)), message + b"\n"
                )

    def test_sign_with_private_verify_with_public(self) -> None:
        message: bytes = b"signed"
        self.assertEqual(self.public.decipher(self.private.cipher(message)), message + b"\n")

    def test_message_bigger_than_modulus_is_reduced(self) -> None:
        m: int = int.from_bytes(b"\xff" * 64, "little")
        expected: str = le_hex(pow(m, RSA_KEYS.e, RSA_KEYS.n))
        self.assertEqual(self.public.cipher(b"\xff" * 64), (expected + "\n").encode())

    def test_ciphered_value_bigger_than_modulus_is_reduced(self) -> None:
        c: int = int.from_bytes(b"\xff" * 64, "little")
        expected: bytes = pow(c, RSA_KEYS.d, RSA_KEYS.n).to_bytes(64, "little").rstrip(b"\x00") or b"\x00"
        self.assertEqual(self.private.decipher(b"ff" * 64 + b"\n"), expected + b"\n")

    def test_decipher_empty_input_is_zero(self) -> None:
        self.assertEqual(self.private.decipher(b""), b"\x00\n")

    def test_decipher_rejects_invalid_hex(self) -> None:
        with self.assertRaises(MyPgpError):
            self.private.decipher(b"hello\n")

    def test_missing_key(self) -> None:
        with self.assertRaises(MyPgpError):
            Rsa(None, False).cipher(b"hello")

    def test_block_option_is_ignored(self) -> None:
        self.assertEqual(Rsa(RSA_KEYS.public, True).cipher(b"hi"), self.public.cipher(b"hi"))


if __name__ == "__main__":
    unittest.main()
