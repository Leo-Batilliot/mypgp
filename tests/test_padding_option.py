"""Option -p: PKCS#7 for xor / aes, OAEP or PKCS#1 v1.5 for rsa, both for pgp.

Without -p nothing changes (see test_subject.py); with -p every round trip gives
back exactly the message: no 00 padding left, no trailing 00 lost through RSA.
"""
from __future__ import annotations

import os
import unittest

from errors import MyPgpError
from padding import oaep_decode, pkcs1_decode
from systems.aes import Aes
from systems.pgp import PgpAes, PgpXor
from systems.rsa import Rsa
from systems.xor import Xor
from tests.helpers import (
    BIG_RSA_KEYS,
    RSA_KEYS,
    SMALL_RSA_KEYS,
    RsaOracle,
    le_int,
    modulus_size,
    rsa_raw_decrypt,
    xor_stream_oracle,
)

XOR_KEY: str = "6b6579"
AES_KEY: str = bytes(range(1, 17)).hex()
MESSAGES: tuple[bytes, ...] = (b"", b"a", b"abc", b"x" * 16, b"ends with zeros\x00\x00", os.urandom(100))


class TestSymmetricPadding(unittest.TestCase):
    def test_xor_ciphers_the_pkcs7_padded_message(self) -> None:
        # "abc" is exactly one 3-byte block: PKCS#7 adds a whole block of 03
        expected: bytes = xor_stream_oracle(b"abc\x03\x03\x03", bytes.fromhex(XOR_KEY))
        self.assertEqual(Xor(XOR_KEY, False, "oaep").cipher(b"abc"), (expected.hex() + "\n").encode())

    def test_aes_ciphers_the_pkcs7_padded_message(self) -> None:
        padded: bytes = b"abc" + bytes([13]) * 13
        expected: bytes = Aes(AES_KEY, True).cipher(padded)
        self.assertEqual(Aes(AES_KEY, False, "oaep").cipher(b"abc"), expected)

    def test_round_trip_gives_back_the_exact_message(self) -> None:
        for system, key in ((Xor, XOR_KEY), (Xor, "41"), (Aes, AES_KEY), (Aes, "00" * 32)):
            for message in MESSAGES:
                padded = system(key, False, "oaep")
                with self.subTest(system=system.name, key=key[:6], message=message[:8]):
                    self.assertEqual(padded.decipher(padded.cipher(message)), message + b"\n")

    def test_invalid_padding_is_rejected(self) -> None:
        # "abc" ciphered without padding: its last byte is not a valid PKCS#7 padding
        ciphered: bytes = Xor(XOR_KEY, False).cipher(b"abc")
        with self.assertRaises(MyPgpError):
            Xor(XOR_KEY, False, "oaep").decipher(ciphered)

    def test_ciphered_message_must_be_whole_blocks(self) -> None:
        with self.assertRaises(MyPgpError):
            Aes(AES_KEY, False, "oaep").decipher(b"00" * 17)

    def test_no_padding_in_block_mode(self) -> None:
        for system, key in ((Xor, XOR_KEY), (Aes, AES_KEY)):
            with self.subTest(system=system.name), self.assertRaises(MyPgpError):
                system(key, True, "oaep")

    def test_xor_key_longer_than_255_bytes(self) -> None:
        with self.assertRaises(MyPgpError):
            Xor("41" * 256, False, "oaep").check_key("-c")
        Xor("41" * 255, False, "oaep").check_key("-c")


class TestRsaPadding(unittest.TestCase):
    def round_trip(self, message: bytes, padding: str, keys: RsaOracle) -> bytes:
        ciphered: bytes = Rsa(keys.public, False, padding).cipher(message)
        return Rsa(keys.private, False, padding).decipher(ciphered)

    def test_oaep_layout_seen_with_pow(self) -> None:
        ciphered: bytes = Rsa(BIG_RSA_KEYS.public, False, "oaep").cipher(b"hello")
        em: bytes = rsa_raw_decrypt(le_int(ciphered.decode().strip()), BIG_RSA_KEYS)
        self.assertEqual(oaep_decode(em, modulus_size(BIG_RSA_KEYS)), b"hello")

    def test_pkcs1_layout_seen_with_pow(self) -> None:
        ciphered: bytes = Rsa(RSA_KEYS.public, False, "pkcs1").cipher(b"hello")
        em: bytes = rsa_raw_decrypt(le_int(ciphered.decode().strip()), RSA_KEYS)
        self.assertEqual(em[:2], b"\x00\x02")
        self.assertEqual(pkcs1_decode(em, modulus_size(RSA_KEYS)), b"hello")

    def test_round_trips_keep_trailing_zero_bytes(self) -> None:
        for padding, keys in (("oaep", BIG_RSA_KEYS), ("pkcs1", RSA_KEYS), ("pkcs1", BIG_RSA_KEYS)):
            for message in (b"", b"WF", b"ends with zeros\x00\x00", b"\x00"):
                with self.subTest(padding=padding, message=message):
                    self.assertEqual(self.round_trip(message, padding, keys), message + b"\n")

    def test_padded_cipher_is_randomized(self) -> None:
        for padding, keys in (("oaep", BIG_RSA_KEYS), ("pkcs1", RSA_KEYS)):
            rsa = Rsa(keys.public, False, padding)
            with self.subTest(padding=padding):
                self.assertNotEqual(rsa.cipher(b"same"), rsa.cipher(b"same"))

    def test_message_too_long_for_the_modulus(self) -> None:
        cases = (("oaep", RSA_KEYS, b"a"), ("pkcs1", RSA_KEYS, bytes(54)), ("pkcs1", SMALL_RSA_KEYS, b""))
        for padding, keys, message in cases:
            with self.subTest(padding=padding, size=modulus_size(keys)), self.assertRaises(MyPgpError):
                Rsa(keys.public, False, padding).cipher(message)

    def test_unpadded_ciphered_message_is_rejected(self) -> None:
        ciphered: bytes = Rsa(RSA_KEYS.public, False).cipher(b"hello")
        for padding in ("oaep", "pkcs1"):
            with self.subTest(padding=padding), self.assertRaises(MyPgpError):
                Rsa(RSA_KEYS.private, False, padding).decipher(ciphered)

    def test_wrong_scheme_is_rejected(self) -> None:
        ciphered: bytes = Rsa(BIG_RSA_KEYS.public, False, "oaep").cipher(b"hello")
        with self.assertRaises(MyPgpError):
            Rsa(BIG_RSA_KEYS.private, False, "pkcs1").decipher(ciphered)


class TestPgpPadding(unittest.TestCase):
    def round_trip(self, system: type, sym_key: str, message: bytes, block: bool, padding: str,
                   keys: RsaOracle) -> bytes:
        output: bytes = system(f"{sym_key}:{keys.public}", block, padding).cipher(message)
        first_line, _, rest = output.partition(b"\n")
        return system(f"{first_line.decode()}:{keys.private}", block, padding).decipher(rest)

    def test_stream_round_trips(self) -> None:
        cases = ((PgpXor, XOR_KEY, "pkcs1", RSA_KEYS), (PgpAes, AES_KEY, "pkcs1", RSA_KEYS),
                 (PgpXor, XOR_KEY, "oaep", BIG_RSA_KEYS), (PgpAes, AES_KEY, "oaep", BIG_RSA_KEYS))
        for system, sym_key, padding, keys in cases:
            for message in MESSAGES:
                with self.subTest(system=system.name, padding=padding, message=message[:8]):
                    self.assertEqual(self.round_trip(system, sym_key, message, False, padding, keys), message + b"\n")

    def test_key_ending_with_zero_bytes_survives(self) -> None:
        # Without -p, the trailing 00 of the key is lost through RSA (see test_pgp.py)
        for system, sym_key in ((PgpXor, "6b6500"), (PgpAes, "41" * 14 + "0000")):
            with self.subTest(system=system.name):
                self.assertEqual(self.round_trip(system, sym_key, b"hello", False, "pkcs1", RSA_KEYS), b"hello\n")

    def test_block_mode_pads_only_the_key(self) -> None:
        output: bytes = PgpAes(f"{AES_KEY}:{RSA_KEYS.public}", True, "pkcs1").cipher(b"x" * 16)
        self.assertEqual(output.split(b"\n")[1], Aes(AES_KEY, True).cipher(b"x" * 16).strip())
        self.assertEqual(self.round_trip(PgpAes, AES_KEY, b"x" * 16, True, "pkcs1", RSA_KEYS), b"x" * 16 + b"\n")

    def test_ciphered_key_is_the_padded_key(self) -> None:
        output: bytes = PgpAes(f"{AES_KEY}:{RSA_KEYS.public}", False, "pkcs1").cipher(b"hi")
        em: bytes = rsa_raw_decrypt(le_int(output.split(b"\n")[0].decode()), RSA_KEYS)
        self.assertEqual(pkcs1_decode(em, modulus_size(RSA_KEYS)), bytes.fromhex(AES_KEY))

    def test_oaep_needs_a_bigger_modulus_than_the_256_bit_primes(self) -> None:
        with self.assertRaises(MyPgpError):
            PgpAes(f"{AES_KEY}:{RSA_KEYS.public}", False, "oaep").cipher(b"hi")


if __name__ == "__main__":
    unittest.main()
