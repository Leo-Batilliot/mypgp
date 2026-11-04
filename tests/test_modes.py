"""Option -m: mode of operation of the stream mode (aes, pgp-aes).

  -m ecb   the subject's stream mode: each block on its own (default)
  -m cbc   out = IV || C1 || C2...   C[i] = AES(P[i] ^ C[i - 1]), C[0] = IV, padded as without -m
  -m ctr   out = N || P ^ keystream  keystream = AES(N) || AES(N + 1)...: nothing padded

modes.py is checked with the standard AES core against NIST SP 800-38A. The systems use the
Epitech AES block (the one of `aes -b`), so their expected values are built from `aes -b`.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from aes_core import AesCore
from errors import MyPgpError
from modes import cbc_decrypt, cbc_encrypt, ctr_crypt, new_iv
from systems.aes import Aes
from systems.pgp import PgpAes
from tests.helpers import BIG_RSA_KEYS, NIST_CBC, NIST_CTR, NIST_KEY, NIST_PLAINTEXT, RSA_KEYS, RsaOracle, zero_pad

AES_KEY: str = bytes(range(1, 17)).hex()
MESSAGES: tuple[bytes, ...] = (b"", b"a", b"x" * 16, b"y" * 17, b"ends with zeros\x00\x00", os.urandom(100))


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aes_block(key: str, block: bytes) -> bytes:
    """One block ciphered like `aes -c -b`."""
    return bytes.fromhex(Aes(key, True).cipher(block).decode())


def cbc_oracle(key: str, iv: bytes, message: bytes) -> bytes:
    previous: bytes = iv
    blocks: list[bytes] = []
    for i in range(0, len(message), 16):
        previous = aes_block(key, xor(message[i:i + 16], previous))
        blocks.append(previous)
    return b"".join(blocks)


def ctr_oracle(key: str, counter: bytes, message: bytes) -> bytes:
    start: int = int.from_bytes(counter, "big")
    keystream: bytes = b"".join(
        aes_block(key, ((start + i) % 2 ** 128).to_bytes(16, "big")) for i in range(len(message) // 16 + 1)
    )
    return xor(message, keystream)


def output_bytes(output: bytes) -> bytes:
    return bytes.fromhex(output.decode().strip())


class TestNistVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.core: AesCore = AesCore(bytes.fromhex(NIST_KEY))
        self.plaintext: bytes = bytes.fromhex(NIST_PLAINTEXT)

    def test_cbc_encrypt(self) -> None:
        iv, expected = NIST_CBC
        self.assertEqual(cbc_encrypt(self.core.encrypt_block, bytes.fromhex(iv), self.plaintext).hex(), expected)

    def test_cbc_decrypt(self) -> None:
        iv, ciphered = NIST_CBC
        deciphered: bytes = cbc_decrypt(self.core.decrypt_block, bytes.fromhex(iv), bytes.fromhex(ciphered))
        self.assertEqual(deciphered.hex(), NIST_PLAINTEXT)

    def test_ctr_both_ways(self) -> None:
        counter, ciphered = NIST_CTR
        self.assertEqual(ctr_crypt(self.core.encrypt_block, bytes.fromhex(counter), self.plaintext).hex(), ciphered)
        deciphered: bytes = ctr_crypt(self.core.encrypt_block, bytes.fromhex(counter), bytes.fromhex(ciphered))
        self.assertEqual(deciphered.hex(), NIST_PLAINTEXT)

    def test_ctr_partial_block_is_cut_not_padded(self) -> None:
        counter, ciphered = NIST_CTR
        for length in (0, 1, 15, 17, 63):
            with self.subTest(length=length):
                result: bytes = ctr_crypt(self.core.encrypt_block, bytes.fromhex(counter), self.plaintext[:length])
                self.assertEqual(result.hex(), ciphered[:2 * length])

    def test_ctr_counter_wraps_around(self) -> None:
        # openssl enc -aes-128-ctr -iv ffffffffffffffffffffffffffffffff on 20 zero bytes
        keystream: bytes = ctr_crypt(self.core.encrypt_block, b"\xff" * 16, bytes(20))
        self.assertEqual(keystream.hex(), "8af2860142f786f409307c1a3f7eaaac7df76b0c")

    def test_new_iv(self) -> None:
        self.assertEqual(len(new_iv(16)), 16)
        self.assertNotEqual(new_iv(16), new_iv(16))


class TestAesCbc(unittest.TestCase):
    def test_output_is_iv_then_chained_blocks(self) -> None:
        for message in MESSAGES:
            output: bytes = output_bytes(Aes(AES_KEY, False, operation="cbc").cipher(message))
            iv, ciphered = output[:16], output[16:]
            with self.subTest(message=message[:8]):
                self.assertEqual(ciphered, cbc_oracle(AES_KEY, iv, zero_pad(message, 16)))

    def test_equal_blocks_no_longer_give_equal_ciphered_blocks(self) -> None:
        message: bytes = b"Winter is coming" * 2
        ecb: bytes = output_bytes(Aes(AES_KEY, False).cipher(message))
        cbc: bytes = output_bytes(Aes(AES_KEY, False, operation="cbc").cipher(message))[16:]
        self.assertEqual(ecb[:16], ecb[16:])
        self.assertNotEqual(cbc[:16], cbc[16:])

    def test_with_a_zero_iv_the_first_block_is_the_ecb_one(self) -> None:
        with mock.patch("systems.base.new_iv", return_value=bytes(16)):
            output: bytes = output_bytes(Aes(AES_KEY, False, operation="cbc").cipher(b"All men must die"))
        self.assertEqual(output, bytes(16) + output_bytes(Aes(AES_KEY, True).cipher(b"All men must die")))

    def test_same_message_twice_gives_two_outputs(self) -> None:
        aes: Aes = Aes(AES_KEY, False, operation="cbc")
        self.assertNotEqual(aes.cipher(b"hello"), aes.cipher(b"hello"))

    def test_round_trip(self) -> None:
        for key in (AES_KEY, "00" * 24, "ff" * 32):
            for message in MESSAGES:
                with self.subTest(key=key[:6], message=message[:8]):
                    plain: Aes = Aes(key, False, operation="cbc")
                    self.assertEqual(plain.decipher(plain.cipher(message)), zero_pad(message, 16) + b"\n")
                    padded: Aes = Aes(key, False, "oaep", operation="cbc")
                    self.assertEqual(padded.decipher(padded.cipher(message)), message + b"\n")

    def test_decipher_errors(self) -> None:
        aes: Aes = Aes(AES_KEY, False, operation="cbc")
        for ciphered in (b"", b"00" * 15, b"00" * 17, b"00" * 33, b"zz"):
            with self.subTest(ciphered=ciphered), self.assertRaises(MyPgpError):
                aes.decipher(ciphered)
        # Ciphered without -p: the 00 padding is not a valid PKCS#7 padding
        with self.assertRaises(MyPgpError):
            Aes(AES_KEY, False, "oaep", operation="cbc").decipher(aes.cipher(b"abc"))

    def test_only_the_iv_for_an_empty_message(self) -> None:
        self.assertEqual(len(output_bytes(Aes(AES_KEY, False, operation="cbc").cipher(b""))), 16)


class TestAesCtr(unittest.TestCase):
    def test_output_is_counter_then_message_xor_keystream(self) -> None:
        for message in MESSAGES:
            output: bytes = output_bytes(Aes(AES_KEY, False, operation="ctr").cipher(message))
            counter, ciphered = output[:16], output[16:]
            with self.subTest(message=message[:8]):
                self.assertEqual(len(ciphered), len(message))
                self.assertEqual(ciphered, ctr_oracle(AES_KEY, counter, message))

    def test_round_trip_is_exact(self) -> None:
        for key in (AES_KEY, "00" * 24, "ff" * 32):
            for message in MESSAGES:
                aes: Aes = Aes(key, False, operation="ctr")
                with self.subTest(key=key[:6], message=message[:8]):
                    self.assertEqual(aes.decipher(aes.cipher(message)), message + b"\n")

    def test_flipping_a_ciphered_bit_flips_the_same_message_bit(self) -> None:
        # CTR hides the message but does not protect it: that is what -a is for
        aes: Aes = Aes(AES_KEY, False, operation="ctr")
        output: bytearray = bytearray(output_bytes(aes.cipher(b"pay 100 to Arya")))
        output[16 + 4] ^= ord("1") ^ ord("9")
        self.assertEqual(aes.decipher(output.hex().encode()), b"pay 900 to Arya\n")

    def test_decipher_errors(self) -> None:
        for ciphered in (b"", b"00" * 15, b"zz"):
            with self.subTest(ciphered=ciphered), self.assertRaises(MyPgpError):
                Aes(AES_KEY, False, operation="ctr").decipher(ciphered)


class TestPgpAes(unittest.TestCase):
    def round_trip(self, message: bytes, operation: str, padding: str | None = None,
                   keys: RsaOracle = RSA_KEYS) -> bytes:
        output: bytes = PgpAes(f"{AES_KEY}:{keys.public}", False, padding, operation=operation).cipher(message)
        ciphered_key, _, ciphered = output.partition(b"\n")
        return PgpAes(f"{ciphered_key.decode()}:{keys.private}", False, padding, operation=operation).decipher(ciphered)

    def test_second_line_is_the_aes_output(self) -> None:
        output: bytes = PgpAes(f"{AES_KEY}:{RSA_KEYS.public}", False, operation="ctr").cipher(b"hello")
        ciphered: bytes = output_bytes(output.split(b"\n")[1])
        self.assertEqual(ciphered[16:], ctr_oracle(AES_KEY, ciphered[:16], b"hello"))

    def test_round_trips(self) -> None:
        for message in MESSAGES:
            with self.subTest(message=message[:8]):
                self.assertEqual(self.round_trip(message, "cbc"), zero_pad(message, 16) + b"\n")
                self.assertEqual(self.round_trip(message, "ctr"), message + b"\n")
                self.assertEqual(self.round_trip(message, "cbc", "oaep", BIG_RSA_KEYS), message + b"\n")

    def test_ctr_with_padding_only_pads_the_rsa_key(self) -> None:
        self.assertEqual(self.round_trip(b"abc", "ctr", "oaep", BIG_RSA_KEYS), b"abc\n")


if __name__ == "__main__":
    unittest.main()
