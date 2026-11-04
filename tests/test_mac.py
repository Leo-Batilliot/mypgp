"""HMAC-SHA256 (mac.py) and option -a: encrypt-then-MAC (xor, aes, pgp-xor, pgp-aes).

  out = hex(ciphered || tag)   tag = HMAC-SHA256(MAC_KEY, ciphered), 32 bytes
  MAC_KEY = HMAC-SHA256("my_pgp authentication key", symmetric key)   (HKDF-Extract)

The tag is checked before anything is deciphered. HMAC is compared with Python's hmac module.
"""
from __future__ import annotations

import os
import unittest

from errors import MyPgpError
from mac import constant_time_equal, derive_key, hmac_sha256
from systems.aes import Aes
from systems.base import SymmetricSystem
from systems.pgp import PgpAes, PgpXor
from systems.xor import Xor
from tests.helpers import RSA_KEYS, hmac_oracle, mac_key_oracle, split_tag

XOR_KEY: str = "6b6579"
AES_KEY: str = bytes(range(1, 17)).hex()


class TestHmac(unittest.TestCase):
    def test_rfc_4231_test_case_2(self) -> None:
        self.assertEqual(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )

    def test_matches_hmac_module(self) -> None:
        # Keys shorter than, as long as and longer than a SHA-256 block (64 bytes, hashed first)
        for key_size in (0, 1, 32, 63, 64, 65, 200):
            for data_size in (0, 1, 55, 56, 64, 1000):
                key, data = os.urandom(key_size), os.urandom(data_size)
                with self.subTest(key_size=key_size, data_size=data_size):
                    self.assertEqual(hmac_sha256(key, data), hmac_oracle(key, data))

    def test_derive_key(self) -> None:
        self.assertEqual(derive_key(b"key", b"label"), hmac_oracle(b"label", b"key"))
        self.assertNotEqual(derive_key(b"key", b"one use"), derive_key(b"key", b"another use"))

    def test_trailing_zeros_of_a_key(self) -> None:
        # HMAC pads its key with 00: these two keys are the same HMAC key...
        self.assertEqual(hmac_sha256(b"ke", b"data"), hmac_sha256(b"ke\x00", b"data"))
        # ...but not the same derived key (a PGP key ending with 00 loses it through RSA)
        self.assertNotEqual(derive_key(b"ke", b"label"), derive_key(b"ke\x00", b"label"))

    def test_constant_time_equal(self) -> None:
        self.assertTrue(constant_time_equal(b"", b""))
        self.assertTrue(constant_time_equal(b"abcd", b"abcd"))
        for other in (b"abce", b"bbcd", b"abc", b"abcde", b""):
            with self.subTest(other=other):
                self.assertFalse(constant_time_equal(b"abcd", other))


def systems() -> list[tuple[str, SymmetricSystem]]:
    return [
        ("xor", Xor(XOR_KEY, False, authenticated=True)),
        ("aes", Aes(AES_KEY, False, authenticated=True)),
        ("aes cbc", Aes(AES_KEY, False, operation="cbc", authenticated=True)),
        ("aes ctr", Aes(AES_KEY, False, operation="ctr", authenticated=True)),
        ("aes cbc -p", Aes(AES_KEY, False, "oaep", operation="cbc", authenticated=True)),
    ]


class TestAuthentication(unittest.TestCase):
    def test_tag_follows_the_unchanged_ciphered_message(self) -> None:
        for system, key in ((Xor, XOR_KEY), (Aes, AES_KEY)):
            with self.subTest(system=system.name):
                ciphered, tag = split_tag(system(key, False, authenticated=True).cipher(b"hello world"))
                self.assertEqual((ciphered.hex() + "\n").encode(), system(key, False).cipher(b"hello world"))
                self.assertEqual(tag, hmac_oracle(mac_key_oracle(key), ciphered))

    def test_tag_covers_the_iv(self) -> None:
        ciphered, tag = split_tag(Aes(AES_KEY, False, operation="cbc", authenticated=True).cipher(b"hello"))
        self.assertEqual(len(ciphered), 32)
        self.assertEqual(tag, hmac_oracle(mac_key_oracle(AES_KEY), ciphered))

    def test_round_trip(self) -> None:
        for name, system in systems():
            for message in (b"", b"a", b"hello world", os.urandom(100)):
                plain: SymmetricSystem = type(system)(system.key, False, system.padding, operation=system.operation)
                ciphered, _ = split_tag(system.cipher(message))
                with self.subTest(system=name, message=message[:8]):
                    self.assertEqual(system.decipher(system.cipher(message)), plain.decipher(ciphered.hex().encode()))

    def test_any_modified_byte_is_rejected(self) -> None:
        for name, system in systems():
            output: bytes = bytes.fromhex(system.cipher(b"hello").decode())
            for i in range(len(output)):
                forged: bytearray = bytearray(output)
                forged[i] ^= 1
                with self.subTest(system=name, byte=i), self.assertRaises(MyPgpError):
                    system.decipher(forged.hex().encode())

    def test_truncated_or_extended_message_is_rejected(self) -> None:
        output: bytes = bytes.fromhex(Aes(AES_KEY, False, authenticated=True).cipher(b"hello").decode())
        for forged in (output[:-1], output[1:], output + b"\x00", output[:32], b"", bytes(31)):
            with self.subTest(size=len(forged)), self.assertRaises(MyPgpError):
                Aes(AES_KEY, False, authenticated=True).decipher(forged.hex().encode())

    def test_wrong_key_is_rejected(self) -> None:
        ciphered: bytes = Xor(XOR_KEY, False, authenticated=True).cipher(b"hello")
        with self.assertRaises(MyPgpError):
            Xor("6b657a", False, authenticated=True).decipher(ciphered)

    def test_tag_key_comes_from_the_key_bytes(self) -> None:
        ciphered: bytes = Xor(XOR_KEY.upper(), False, authenticated=True).cipher(b"hello")
        self.assertEqual(Xor(XOR_KEY, False, authenticated=True).decipher(ciphered), b"hello\x00\n")

    def test_the_whole_ciphered_message_is_checked_before_deciphering(self) -> None:
        # Not a whole number of blocks: with a valid tag this would be a CBC error, here
        # the forged tag is what is reported
        forged: bytes = (bytes(17) + bytes(32)).hex().encode()
        with self.assertRaisesRegex(MyPgpError, "invalid tag"):
            Aes(AES_KEY, False, operation="cbc", authenticated=True).decipher(forged)


class TestPgpAuthentication(unittest.TestCase):
    def round_trip(self, system: type, sym_key: str, message: bytes) -> bytes:
        output: bytes = system(f"{sym_key}:{RSA_KEYS.public}", False, authenticated=True).cipher(message)
        ciphered_key, _, ciphered = output.partition(b"\n")
        return system(f"{ciphered_key.decode()}:{RSA_KEYS.private}", False, authenticated=True).decipher(ciphered)

    def test_second_line_is_authenticated(self) -> None:
        output: bytes = PgpXor(f"{XOR_KEY}:{RSA_KEYS.public}", False, authenticated=True).cipher(b"hello")
        ciphered, tag = split_tag(output.split(b"\n")[1])
        self.assertEqual(tag, hmac_oracle(mac_key_oracle(XOR_KEY), ciphered))

    def test_round_trips(self) -> None:
        self.assertEqual(self.round_trip(PgpXor, XOR_KEY, b"hello world"), b"hello world\x00\n")
        self.assertEqual(self.round_trip(PgpAes, AES_KEY, b"hello world"), b"hello world" + bytes(5) + b"\n")

    def test_key_changed_through_rsa_is_detected(self) -> None:
        # Without -p the trailing 00 of the key is lost through RSA: without -a the message
        # comes back wrong (see test_pgp.py), with -a the wrong key is detected
        with self.assertRaisesRegex(MyPgpError, "invalid tag"):
            self.round_trip(PgpXor, "6b6500", b"abcdefg")


if __name__ == "__main__":
    unittest.main()
