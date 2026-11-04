"""dh: Diffie-Hellman key agreement, then AES-256 in CTR mode with an HMAC tag.

  -g P X / -g -r   the ElGamal keys Y-G-P / X-G-P (-g -r: in the RFC 3526 2048-bit group)
  -c / -d          key = MY_PRIVATE_KEY:THEIR_PUBLIC_KEY, any input, given back exactly
                   Alice ciphers with X_A:Y_B, Bob deciphers with X_B:Y_A
  shared secret    S = Y_B^X_A = Y_A^X_B = G^(X_A X_B) mod P
  AES key          SHA-256(S as little-endian bytes, as many as P), then `aes -m ctr -a`
"""
from __future__ import annotations

import hashlib
import os
import unittest

from errors import MyPgpError
from systems.aes import Aes
from systems.dh import MODP_2048, DiffieHellman
from systems.elgamal import ElGamal
from tests.helpers import SAFE_PRIME, SMALL_SAFE_PRIME, elgamal_generator_oracle, is_probable_prime, le_hex, le_int

G: int = elgamal_generator_oracle(SAFE_PRIME)
Q: int = (SAFE_PRIME - 1) // 2
X_ALICE: int = 0x1234567890ABCDEF
X_BOB: int = 0xFEDCBA0987654321


def key(value: int, p: int = SAFE_PRIME, g: int = G) -> str:
    return f"{le_hex(value)}-{le_hex(g)}-{le_hex(p)}"


def dh(private: int, public: int) -> DiffieHellman:
    return DiffieHellman(f"{key(private)}:{key(pow(G, public, SAFE_PRIME))}", False)


def pi_times_2_to_the(bits: int) -> int:
    """floor(pi * 2^bits), with Machin's formula pi = 16 atan(1/5) - 4 atan(1/239)."""
    one: int = 1 << (bits + 64)

    def atan_inverse(x: int) -> int:
        total, term, n, sign = 0, one // x, 1, 1
        while term:
            total += sign * (term // n)
            term, n, sign = term // (x * x), n + 2, -sign
        return total

    return (16 * atan_inverse(5) - 4 * atan_inverse(239)) >> 64


class TestStandardGroup(unittest.TestCase):
    def test_modp_2048_is_the_rfc_3526_prime(self) -> None:
        p: int = 2 ** 2048 - 2 ** 1984 - 1 + 2 ** 64 * (pi_times_2_to_the(1918) + 124476)
        self.assertEqual(MODP_2048, p)
        self.assertTrue(is_probable_prime(p) and is_probable_prime((p - 1) // 2))
        self.assertEqual(elgamal_generator_oracle(p), 2)


class TestKeyGeneration(unittest.TestCase):
    def test_same_keys_as_elgamal(self) -> None:
        self.assertEqual(
            DiffieHellman(None, False).generate("070001", "d204"), ElGamal(None, False).generate("070001", "d204")
        )

    def test_random_keys_are_in_the_standard_group(self) -> None:
        lines: list[str] = DiffieHellman(None, False).generate_random(None).decode().splitlines()
        y, g, p = (le_int(part) for part in lines[0].split(": ", 1)[1].split("-"))
        x, g2, p2 = (le_int(part) for part in lines[1].split(": ", 1)[1].split("-"))
        self.assertEqual((g, p, g2, p2), (2, MODP_2048, 2, MODP_2048))
        self.assertTrue(1 <= x < (p - 1) // 2)
        self.assertEqual(pow(2, x, p), y)
        self.assertNotEqual(
            DiffieHellman(None, False).generate_random(None), DiffieHellman(None, False).generate_random(None)
        )

    def test_random_size_is_refused(self) -> None:
        with self.assertRaises(MyPgpError):
            DiffieHellman(None, False).generate_random(512)


class TestAgreement(unittest.TestCase):
    def test_both_sides_get_the_same_secret(self) -> None:
        alice: DiffieHellman = dh(X_ALICE, X_BOB)
        bob: DiffieHellman = dh(X_BOB, X_ALICE)
        self.assertEqual(alice.secret, bob.secret)
        self.assertEqual(alice.secret, pow(G, X_ALICE * X_BOB, SAFE_PRIME))

    def test_output_is_aes_ctr_with_tag_under_the_hashed_secret(self) -> None:
        secret: int = pow(G, X_ALICE * X_BOB, SAFE_PRIME)
        aes_key: bytes = hashlib.sha256(secret.to_bytes(32, "little")).digest()
        aes: Aes = Aes(aes_key.hex(), False, operation="ctr", authenticated=True)
        ciphered: bytes = dh(X_ALICE, X_BOB).cipher(b"hello")
        self.assertEqual(aes.decipher(ciphered), b"hello\n")
        self.assertEqual(dh(X_BOB, X_ALICE).decipher(aes.cipher(b"hello")), b"hello")

    def test_round_trip_is_exact(self) -> None:
        for message in (b"", b"a", b"hello\n", b"\n\n", b"ends with zeros\x00\x00", os.urandom(1000)):
            with self.subTest(message=message[:12]):
                self.assertEqual(dh(X_BOB, X_ALICE).decipher(dh(X_ALICE, X_BOB).cipher(message)), message)

    def test_standard_group_round_trip(self) -> None:
        keys: list[list[str]] = [
            [line.split(": ")[1] for line in DiffieHellman(None, False).generate_random(None).decode().splitlines()]
            for _ in range(2)
        ]
        (alice_public, alice_private), (bob_public, bob_private) = keys
        ciphered: bytes = DiffieHellman(f"{alice_private}:{bob_public}", False).cipher(b"Winter is coming\n")
        self.assertEqual(DiffieHellman(f"{bob_private}:{alice_public}", False).decipher(ciphered), b"Winter is coming\n")

    def test_other_keys_are_rejected(self) -> None:
        ciphered: bytes = dh(X_ALICE, X_BOB).cipher(b"hello")
        for eve in (dh(0xE7E, X_ALICE), dh(0xE7E, X_BOB), dh(X_BOB, X_BOB)):
            with self.assertRaisesRegex(MyPgpError, "invalid tag"):
                eve.decipher(ciphered)

    def test_modified_message_is_rejected(self) -> None:
        ciphered: bytearray = bytearray(dh(X_ALICE, X_BOB).cipher(b"hello"))
        ciphered[40] = ord("0") if ciphered[40] != ord("0") else ord("1")
        with self.assertRaises(MyPgpError):
            dh(X_BOB, X_ALICE).decipher(bytes(ciphered))


class TestInvalidKeys(unittest.TestCase):
    def test_format(self) -> None:
        for text in (key(X_ALICE), f"{key(X_ALICE)}:{key(5)}:{key(7)}", f"{key(X_ALICE)}:zz", ":"):
            with self.subTest(text=text[:20]), self.assertRaises(MyPgpError):
                DiffieHellman(text, False)

    def test_keys_of_two_groups(self) -> None:
        other: str = key(pow(2, 5, SMALL_SAFE_PRIME), SMALL_SAFE_PRIME, 2)
        with self.assertRaisesRegex(MyPgpError, "same generator and prime"):
            DiffieHellman(f"{key(X_ALICE)}:{other}", False)

    def test_private_value_out_of_range(self) -> None:
        for x in (0, Q, Q + 1):
            with self.subTest(x=x), self.assertRaises(MyPgpError):
                DiffieHellman(f"{key(x)}:{key(pow(G, X_BOB, SAFE_PRIME))}", False)

    def test_public_value_outside_the_group(self) -> None:
        # 1 and P - 1 leave only one or two possible secrets; a non-square is outside
        # the group of order Q generated by G
        non_square: int = next(v for v in range(2, 100) if pow(v, Q, SAFE_PRIME) != 1)
        for y in (0, 1, SAFE_PRIME - 1, non_square, SAFE_PRIME, SAFE_PRIME + 1):
            with self.subTest(y=y), self.assertRaises(MyPgpError):
                DiffieHellman(f"{key(X_ALICE)}:{key(y)}", False)

    def test_cipher_without_key(self) -> None:
        with self.assertRaises(MyPgpError):
            DiffieHellman(None, False).cipher(b"hello")


if __name__ == "__main__":
    unittest.main()
