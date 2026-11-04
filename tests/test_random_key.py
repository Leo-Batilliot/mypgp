"""Option -k (pgp-xor, pgp-aes, -c only): the symmetric key is drawn at random.

  key  RSA_KEY (:SIGNER_RSA_KEY with -s): no SYMMETRIC_KEY
  out  as without -k: the random key ciphered with RSA, then the ciphered message

pgp-aes: the longest AES key that RSA can carry (32, 24, then 16 bytes).
pgp-xor: as long as the message (a one-time pad) if RSA can carry it, otherwise as long as RSA allows.
The last byte of the key is never 00, so the key comes back through RSA with its length.
"""
from __future__ import annotations

import unittest
from unittest import mock

from errors import MyPgpError
from systems.aes import Aes
from systems.pgp import Pgp, PgpAes, PgpXor
from systems.rsa import Rsa
from systems.xor import Xor
from tests.helpers import (
    BIG_RSA_KEYS,
    RSA_KEYS,
    SIGNER_KEYS,
    SMALL_RSA_KEYS,
    RsaOracle,
    is_probable_prime,
    le_hex,
    le_int,
    rsa_oracle,
    zero_pad,
)


def next_prime(n: int) -> int:
    while not is_probable_prime(n):
        n += 1
    return n


# n of 20 bytes (room for 19: a 16-byte AES key) and of 25 bytes (room for 24)
KEYS_20_BYTES: RsaOracle = rsa_oracle(next_prime(1 << 79), next_prime((1 << 79) + (1 << 70)))
KEYS_25_BYTES: RsaOracle = rsa_oracle(next_prime(1 << 99), next_prime((1 << 99) + (1 << 90)))


def recovered_key(output: bytes, keys: RsaOracle) -> bytes:
    """The random key, deciphered from the first line with pow."""
    ciphered_key: int = le_int(output.split(b"\n")[0].decode())
    return bytes.fromhex(le_hex(pow(ciphered_key, keys.d, keys.n)))


def second_line(output: bytes) -> bytes:
    return output.split(b"\n")[1] + b"\n"


class TestPgpAesRandomKey(unittest.TestCase):
    def test_key_size_follows_the_rsa_modulus(self) -> None:
        for keys, size in ((RSA_KEYS, 32), (KEYS_25_BYTES, 24), (KEYS_20_BYTES, 16)):
            output: bytes = PgpAes(keys.public, False, random_key=True).cipher(b"hello")
            key: bytes = recovered_key(output, keys)
            with self.subTest(modulus=(keys.n.bit_length() + 7) // 8):
                self.assertEqual(len(key), size)
                self.assertEqual(second_line(output), Aes(key.hex(), False).cipher(b"hello"))

    def test_padding_leaves_less_room(self) -> None:
        self.assertEqual(PgpAes(BIG_RSA_KEYS.public, False, "oaep", random_key=True).random_key_size(0), 32)
        self.assertEqual(PgpAes(RSA_KEYS.public, False, "pkcs1", random_key=True).random_key_size(0), 32)
        # 64-byte modulus: OAEP takes 66 bytes
        with self.assertRaises(MyPgpError):
            PgpAes(RSA_KEYS.public, False, "oaep", random_key=True).random_key_size(0)

    def test_rsa_key_too_small_is_refused_before_reading_stdin(self) -> None:
        for keys in (SMALL_RSA_KEYS, rsa_oracle(next_prime(1 << 63), next_prime((1 << 63) + (1 << 50)))):
            with self.subTest(n=keys.n.bit_length()), self.assertRaises(MyPgpError):
                PgpAes(keys.public, False, random_key=True).check_key("-c")

    def test_round_trip(self) -> None:
        output: bytes = PgpAes(RSA_KEYS.public, False, random_key=True).cipher(b"All men must die!")
        ciphered_key, _, ciphered = output.partition(b"\n")
        deciphered: bytes = PgpAes(f"{ciphered_key.decode()}:{RSA_KEYS.private}", False).decipher(ciphered)
        self.assertEqual(deciphered, zero_pad(b"All men must die!", 16) + b"\n")

    def test_new_key_each_time(self) -> None:
        pgp: PgpAes = PgpAes(RSA_KEYS.public, False, random_key=True)
        self.assertNotEqual(recovered_key(pgp.cipher(b"x"), RSA_KEYS), recovered_key(pgp.cipher(b"x"), RSA_KEYS))


class TestPgpXorRandomKey(unittest.TestCase):
    def test_key_as_long_as_the_message(self) -> None:
        # RSA_KEYS: 64-byte modulus, room for 63
        for message in (b"a", b"hello", b"x" * 63):
            output: bytes = PgpXor(RSA_KEYS.public, False, random_key=True).cipher(message)
            key: bytes = recovered_key(output, RSA_KEYS)
            with self.subTest(size=len(message)):
                self.assertEqual(len(key), len(message))
                self.assertEqual(second_line(output), Xor(key.hex(), False).cipher(message))

    def test_key_as_long_as_rsa_allows(self) -> None:
        for size, key_size in ((64, 63), (100, 63), (0, 1)):
            output: bytes = PgpXor(RSA_KEYS.public, False, random_key=True).cipher(b"x" * size)
            with self.subTest(size=size):
                self.assertEqual(len(recovered_key(output, RSA_KEYS)), key_size)

    def test_pkcs7_keeps_the_key_under_256_bytes(self) -> None:
        with mock.patch.object(Rsa, "max_message_size", return_value=1000):
            self.assertEqual(PgpXor(RSA_KEYS.public, False, "oaep", random_key=True).random_key_size(300), 255)
            self.assertEqual(PgpXor(RSA_KEYS.public, False, random_key=True).random_key_size(300), 300)

    def test_block_mode(self) -> None:
        output: bytes = PgpXor(RSA_KEYS.public, True, random_key=True).cipher(b"abc")
        self.assertEqual(len(recovered_key(output, RSA_KEYS)), 3)
        with self.assertRaises(MyPgpError):
            PgpXor(RSA_KEYS.public, True, random_key=True).cipher(b"x" * 64)

    def test_one_time_pad_round_trip_is_exact(self) -> None:
        output: bytes = PgpXor(RSA_KEYS.public, False, random_key=True).cipher(b"You know nothing")
        ciphered_key, _, ciphered = output.partition(b"\n")
        deciphered: bytes = PgpXor(f"{ciphered_key.decode()}:{RSA_KEYS.private}", False).decipher(ciphered)
        self.assertEqual(deciphered, b"You know nothing\n")


class TestRandomKey(unittest.TestCase):
    def test_last_byte_is_never_zero(self) -> None:
        pgp: PgpXor = PgpXor(RSA_KEYS.public, False, random_key=True)
        for size in (1, 2, 40):
            keys: list[bytes] = [bytes.fromhex(pgp.random_key(size)) for _ in range(300)]
            with self.subTest(size=size):
                self.assertTrue(all(len(key) == size and key[-1] != 0 for key in keys))

    def test_key_format(self) -> None:
        for system in (PgpXor, PgpAes):
            with self.subTest(system=system.name):
                with self.assertRaisesRegex(MyPgpError, "expected RSA_KEY$"):
                    system(f"6b:{RSA_KEYS.public}", False, random_key=True)
                with self.assertRaisesRegex(MyPgpError, "expected RSA_KEY:SIGNER_RSA_KEY$"):
                    system(RSA_KEYS.public, False, signed=True, random_key=True)

    def test_decipher_is_refused(self) -> None:
        pgp: Pgp = PgpAes(RSA_KEYS.private, False, random_key=True)
        with self.assertRaises(MyPgpError):
            pgp.decipher(b"00" * 16)

    def test_with_signature_and_tag(self) -> None:
        options: dict[str, bool] = {"signed": True, "authenticated": True}
        sender: PgpAes = PgpAes(f"{RSA_KEYS.public}:{SIGNER_KEYS.private}", False, random_key=True, **options)
        ciphered_key, _, ciphered = sender.cipher(b"hello").partition(b"\n")
        receiver: PgpAes = PgpAes(f"{ciphered_key.decode()}:{RSA_KEYS.private}:{SIGNER_KEYS.public}", False, **options)
        self.assertEqual(receiver.decipher(ciphered), zero_pad(b"hello", 16) + b"\n")


if __name__ == "__main__":
    unittest.main()
