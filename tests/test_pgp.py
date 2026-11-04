"""PGP hybrid systems (pgp-xor, pgp-aes).

Protocol tested (as implemented in src/systems/pgp.py):
  cipher   key = SYMMETRIC_KEY:PUBLIC_RSA_KEY
           out = RSA(SYMMETRIC_KEY) on the first line, then the symmetric output
  decipher key = CIPHERED_SYMMETRIC_KEY:PRIVATE_RSA_KEY
           in  = the symmetric ciphered message only (not the first line)
           the symmetric key is used exactly as recovered through RSA
"""
from __future__ import annotations

import os
import unittest

from errors import MyPgpError
from systems.aes import Aes
from systems.pgp import PgpAes, PgpXor
from tests.helpers import (
    RSA_KEYS,
    SMALL_RSA_KEYS,
    RsaOracle,
    le_hex,
    le_int,
    rsa_round_trip,
    xor_block_oracle,
    xor_stream_decipher_oracle,
    xor_stream_oracle,
    zero_pad,
)

XOR_KEY: str = "6b6579"
AES_KEYS: dict[int, str] = {
    16: bytes(range(1, 17)).hex(),
    24: bytes(range(1, 25)).hex(),
    32: bytes(range(1, 33)).hex(),
}


def ciphered_key(sym_key: str, keys: RsaOracle = RSA_KEYS) -> str:
    return le_hex(pow(le_int(sym_key), keys.e, keys.n))


def pgp_round_trip(system: type, sym_key: str, message: bytes, block: bool,
                   keys: RsaOracle = RSA_KEYS) -> bytes:
    output: bytes = system(f"{sym_key}:{keys.public}", block).cipher(message)
    first_line, _, rest = output.partition(b"\n")
    return system(f"{first_line.decode()}:{keys.private}", block).decipher(rest)


def pgp_xor_stream_oracle(sym_key: str, message: bytes, keys: RsaOracle = RSA_KEYS) -> bytes:
    """Decipher output of a pgp-xor stream round trip: the message is ciphered with the
    real key, then deciphered with the key recovered through RSA."""
    ciphered: bytes = xor_stream_oracle(message, bytes.fromhex(sym_key))
    return xor_stream_decipher_oracle(ciphered, rsa_round_trip(sym_key, keys)) + b"\n"


class TestPgpKey(unittest.TestCase):
    def test_missing_key(self) -> None:
        for system in (PgpXor, PgpAes):
            with self.subTest(system=system.name), self.assertRaises(MyPgpError):
                system(None, False)

    def test_bad_key_format(self) -> None:
        bad_keys: tuple[str, ...] = (
            "",
            XOR_KEY,
            RSA_KEYS.public,
            f"{XOR_KEY}:",
            f"{XOR_KEY}:{RSA_KEYS.public}:extra",
            f"{XOR_KEY}:010001",
            f"{XOR_KEY}-{RSA_KEYS.public}",
            f"{XOR_KEY};{RSA_KEYS.public}",
            "::",
        )
        for system in (PgpXor, PgpAes):
            for key in bad_keys:
                with self.subTest(system=system.name, key=key), self.assertRaises(MyPgpError):
                    system(key, False)

    def test_invalid_symmetric_key_is_rejected_before_reading_stdin(self) -> None:
        cases = ((PgpXor, "zz"), (PgpXor, ""), (PgpXor, "6b6"), (PgpAes, "00" * 15), (PgpAes, "zz" * 16))
        for system, sym_key in cases:
            with self.subTest(system=system.name, sym_key=sym_key), self.assertRaises(MyPgpError):
                system(f"{sym_key}:{RSA_KEYS.public}", False).check_key("-c")

    def test_decipher_only_needs_a_number_as_symmetric_key(self) -> None:
        for system in (PgpXor, PgpAes):
            for sym_key in ("", "00", "abcd", " ab cd "):
                with self.subTest(system=system.name, sym_key=sym_key):
                    system(f"{sym_key}:{RSA_KEYS.private}", False).check_key("-d")
            with self.subTest(system=system.name), self.assertRaises(MyPgpError):
                system(f"zz:{RSA_KEYS.private}", False).check_key("-d")

    def test_symmetric_key_bigger_than_modulus_is_ciphered_mod_n(self) -> None:
        output: bytes = PgpXor(f"{XOR_KEY}:{SMALL_RSA_KEYS.public}", False).cipher(b"hello")
        self.assertEqual(output.split(b"\n")[0].decode(), ciphered_key(XOR_KEY, SMALL_RSA_KEYS))

    def test_tiny_rsa_modulus(self) -> None:
        self.assertEqual(PgpXor(f"{XOR_KEY}:03-01", False).cipher(b"abc"), b"00\n080718\n")
        with self.assertRaises(MyPgpError):
            PgpXor(f"{XOR_KEY}:03-00", False).cipher(b"abc")


class TestPgpCipherFormat(unittest.TestCase):
    def test_pgp_xor_output(self) -> None:
        message: bytes = b"hello world"
        output: bytes = PgpXor(f"{XOR_KEY}:{RSA_KEYS.public}", False).cipher(message)
        expected: str = (
            ciphered_key(XOR_KEY) + "\n"
            + xor_stream_oracle(message, bytes.fromhex(XOR_KEY)).hex() + "\n"
        )
        self.assertEqual(output, expected.encode())

    def test_pgp_xor_block_output(self) -> None:
        output: bytes = PgpXor(f"{XOR_KEY}:{RSA_KEYS.public}", True).cipher(b"abc")
        expected: str = ciphered_key(XOR_KEY) + "\n" + xor_block_oracle(b"abc", b"key").hex() + "\n"
        self.assertEqual(output, expected.encode())

    def test_pgp_xor_empty_message(self) -> None:
        output: bytes = PgpXor(f"{XOR_KEY}:{RSA_KEYS.public}", False).cipher(b"")
        self.assertEqual(output, (ciphered_key(XOR_KEY) + "\n\n").encode())

    def test_pgp_aes_output(self) -> None:
        message: bytes = b"hello world"
        for size, key in AES_KEYS.items():
            output: bytes = PgpAes(f"{key}:{RSA_KEYS.public}", False).cipher(message)
            expected: bytes = (ciphered_key(key) + "\n").encode() + Aes(key, False).cipher(message)
            with self.subTest(size=size):
                self.assertEqual(output, expected)

    def test_first_line_decrypts_to_symmetric_key(self) -> None:
        output: bytes = PgpAes(f"{AES_KEYS[16]}:{RSA_KEYS.public}", False).cipher(b"x")
        first_line: str = output.split(b"\n")[0].decode()
        self.assertEqual(pow(le_int(first_line), RSA_KEYS.d, RSA_KEYS.n), le_int(AES_KEYS[16]))


class TestPgpXorRoundTrip(unittest.TestCase):
    def test_stream(self) -> None:
        for message in (b"a", b"hello world", b"multi\nline\n", os.urandom(200)):
            with self.subTest(message=message[:20]):
                self.assertEqual(
                    pgp_round_trip(PgpXor, XOR_KEY, message, False), zero_pad(message, 3) + b"\n"
                )

    def test_block(self) -> None:
        self.assertEqual(pgp_round_trip(PgpXor, XOR_KEY, b"abc", True), b"abc\n")

    def test_random_keys(self) -> None:
        for _ in range(10):
            key: bytes = os.urandom(8)[:-1] + b"\x42"  # non-zero last byte
            with self.subTest(key=key.hex()):
                self.assertEqual(
                    pgp_round_trip(PgpXor, key.hex(), b"hello world", False), b"hello world" + bytes(5) + b"\n"
                )

    def test_block_ciphered_size_mismatch_is_an_error(self) -> None:
        key: str = f"{ciphered_key(XOR_KEY)}:{RSA_KEYS.private}"
        for ciphered in (b"0011\n", b"0011223344\n", b"\n"):
            with self.subTest(ciphered=ciphered), self.assertRaises(MyPgpError):
                PgpXor(key, True).decipher(ciphered)

    def test_stream_partial_last_block_is_zero_padded(self) -> None:
        output: bytes = PgpXor(f"{ciphered_key(XOR_KEY)}:{RSA_KEYS.private}", False).decipher(b"08071800\n")
        self.assertEqual(output, b"abcyek\n")


class TestPgpXorEval(unittest.TestCase):
    """Cases where the key recovered through RSA differs from the real one, and
    other unusual inputs: the program must never exit with 84 on a valid input."""

    def assert_stream(self, sym_key: str, message: bytes, keys: RsaOracle = RSA_KEYS) -> None:
        with self.subTest(sym_key=sym_key, message=message[:16], n=le_hex(keys.n)):
            self.assertEqual(
                pgp_round_trip(PgpXor, sym_key, message, False, keys),
                pgp_xor_stream_oracle(sym_key, message, keys),
            )

    def test_key_ending_with_zero_bytes(self) -> None:
        for sym_key in ("6b6500", "6b0000", "a1b2c3d400", "ff" * 25 + "00"):
            for message in (b"abcdefg", b"x", b"You know nothing, Jon Snow", b""):
                self.assert_stream(sym_key, message)

    def test_key_bigger_than_modulus(self) -> None:
        for sym_key in (XOR_KEY, "a1b2c3d4", "576861742069732064656164206d6179206e6576657220646965"):
            for message in (b"abc", b"hellowor", b"hello world!!", b"The night is dark"):
                self.assert_stream(sym_key, message, SMALL_RSA_KEYS)

    def test_key_bigger_than_256_bit_modulus(self) -> None:
        sym_key: str = "ff" * 70
        self.assert_stream(sym_key, b"a long message " * 10)

    def test_key_made_of_zeros(self) -> None:
        for sym_key in ("00", "0000", "00" * 16):
            for message in (b"abc", b"hello world"):
                self.assert_stream(sym_key, message)

    def test_one_byte_key(self) -> None:
        for sym_key in ("01", "41", "ff"):
            self.assert_stream(sym_key, b"hello world")
            self.assert_stream(sym_key, b"hello world", SMALL_RSA_KEYS)

    def test_binary_message_with_nul_bytes(self) -> None:
        self.assert_stream(XOR_KEY, b"\x00ab\x00\x00")
        self.assert_stream("a1b2c300", bytes(range(256)))

    def test_block_with_shortened_key_is_an_error(self) -> None:
        for sym_key, keys in (("6b6500", RSA_KEYS), ("a1b2c3d4", SMALL_RSA_KEYS)):
            with self.subTest(sym_key=sym_key), self.assertRaises(MyPgpError):
                pgp_round_trip(PgpXor, sym_key, bytes(len(bytes.fromhex(sym_key))), True, keys)

    def test_block_with_one_byte_key_smaller_than_modulus(self) -> None:
        """"ff" is smaller than n = 47897: same length, the round trip works."""
        self.assertEqual(pgp_round_trip(PgpXor, "ff", b"z", True, SMALL_RSA_KEYS), b"z\n")

    def test_decipher_empty_input(self) -> None:
        key: str = f"{ciphered_key(XOR_KEY)}:{RSA_KEYS.private}"
        for ciphered in (b"", b"\n", b" \n"):
            with self.subTest(ciphered=ciphered):
                self.assertEqual(PgpXor(key, False).decipher(ciphered), b"\n")

    def test_decipher_hex_with_whitespace(self) -> None:
        key: str = f"{ciphered_key(XOR_KEY)}:{RSA_KEYS.private}"
        for ciphered in (b"080718", b" 080718\n", b"0807 18\n", b"0807\n18\n", b"080718\n\n", b"080718".upper()):
            with self.subTest(ciphered=ciphered):
                self.assertEqual(PgpXor(key, False).decipher(ciphered), b"abc\n")

    def test_decipher_keys_with_whitespace(self) -> None:
        key: str = f" {ciphered_key(XOR_KEY)} : {RSA_KEYS.private.replace('-', ' - ')} "
        self.assertEqual(PgpXor(key, False).decipher(b"080718\n"), b"abc\n")

    def test_decipher_empty_ciphered_symmetric_key(self) -> None:
        """An empty number is 0, which RSA turns into the one-byte key 00 (1-byte blocks)."""
        self.assertEqual(PgpXor(f":{RSA_KEYS.private}", False).decipher(b"6162\n"), b"ab\n")

    def test_decipher_invalid_input(self) -> None:
        key: str = f"{ciphered_key(XOR_KEY)}:{RSA_KEYS.private}"
        for ciphered in (b"080\n", b"zz\n", b"08 0 718\n", "é".encode()):
            with self.subTest(ciphered=ciphered), self.assertRaises(MyPgpError):
                PgpXor(key, False).decipher(ciphered)


class TestPgpAesRoundTrip(unittest.TestCase):
    def test_stream(self) -> None:
        for size, key in AES_KEYS.items():
            for message in (b"a", b"hello world", b"a much longer message spanning blocks"):
                with self.subTest(size=size, message=message):
                    self.assertEqual(
                        pgp_round_trip(PgpAes, key, message, False), zero_pad(message, 16) + b"\n"
                    )

    def test_block(self) -> None:
        for size, key in AES_KEYS.items():
            with self.subTest(size=size):
                self.assertEqual(
                    pgp_round_trip(PgpAes, key, b"0123456789abcdef", True), b"0123456789abcdef\n"
                )

    def test_random_keys(self) -> None:
        for size in (16, 24, 32):
            key: str = (os.urandom(size - 1) + b"\x42").hex()
            with self.subTest(key=key):
                self.assertEqual(
                    pgp_round_trip(PgpAes, key, b"hello world", False), b"hello world" + bytes(5) + b"\n"
                )

    def test_key_ending_with_zero_bytes_is_rejected(self) -> None:
        """The recovered key is shorter than 16, 24 or 32 bytes: it is not an AES key."""
        for size in (16, 24, 32):
            key: str = (bytes(range(1, size)) + bytes(1)).hex()
            with self.subTest(size=size), self.assertRaises(MyPgpError):
                pgp_round_trip(PgpAes, key, b"hello world", False)

    def test_24_byte_key_ending_with_8_zero_bytes_is_read_as_aes_128(self) -> None:
        key: str = (bytes(range(1, 17)) + bytes(8)).hex()
        self.assertNotEqual(pgp_round_trip(PgpAes, key, b"hello world", False), b"hello world" + bytes(5) + b"\n")

    def test_key_bigger_than_modulus_is_rejected(self) -> None:
        with self.assertRaises(MyPgpError):
            pgp_round_trip(PgpAes, AES_KEYS[16], b"hello world", False, SMALL_RSA_KEYS)


if __name__ == "__main__":
    unittest.main()
