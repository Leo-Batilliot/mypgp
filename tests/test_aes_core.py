"""Raw AES (FIPS-197, big-endian, no Epitech convention)."""
from __future__ import annotations

import os
import unittest

from aes_core import INV_SBOX, MUL, SBOX, AesCore, gf_inverse, gmul, xtime
from errors import MyPgpError
from tests.helpers import FIPS_APPENDIX_B, FIPS_PLAINTEXT, FIPS_VECTORS


class TestGaloisField(unittest.TestCase):
    def test_xtime(self) -> None:
        # FIPS-197 section 4.2.1
        self.assertEqual(xtime(0x57), 0xAE)
        self.assertEqual(xtime(0xAE), 0x47)
        self.assertEqual(xtime(0x47), 0x8E)
        self.assertEqual(xtime(0x8E), 0x07)

    def test_gmul(self) -> None:
        # FIPS-197 section 4.2: {57} . {83} = {c1}, {57} . {13} = {fe}
        self.assertEqual(gmul(0x57, 0x83), 0xC1)
        self.assertEqual(gmul(0x57, 0x13), 0xFE)
        self.assertEqual(gmul(0x57, 0x01), 0x57)
        self.assertEqual(gmul(0x57, 0x00), 0x00)

    def test_gf_inverse(self) -> None:
        for a in range(1, 256):
            with self.subTest(a=a):
                self.assertEqual(gmul(a, gf_inverse(a)), 1)

    def test_mul_tables_match_gmul(self) -> None:
        self.assertEqual(sorted(MUL), [2, 3, 9, 11, 13, 14])
        for c, table in MUL.items():
            with self.subTest(c=c):
                self.assertEqual(list(table), [gmul(c, x) for x in range(256)])


class TestSboxes(unittest.TestCase):
    def test_known_sbox_values(self) -> None:
        # FIPS-197 figure 7
        self.assertEqual(SBOX[0x00], 0x63)
        self.assertEqual(SBOX[0x01], 0x7C)
        self.assertEqual(SBOX[0x53], 0xED)
        self.assertEqual(SBOX[0xFF], 0x16)

    def test_sbox_is_a_permutation(self) -> None:
        self.assertEqual(sorted(SBOX), list(range(256)))

    def test_inv_sbox_inverts_sbox(self) -> None:
        for x in range(256):
            self.assertEqual(INV_SBOX[SBOX[x]], x)


class TestRoundOperations(unittest.TestCase):
    def test_shift_rows(self) -> None:
        state: list[int] = list(range(16))
        self.assertEqual(
            AesCore.shift_rows(state),
            [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11],
        )

    def test_inv_shift_rows_inverts(self) -> None:
        for state in (list(range(16)), list(os.urandom(16))):
            with self.subTest(state=state):
                self.assertEqual(AesCore.inv_shift_rows(AesCore.shift_rows(state)), state)
                self.assertEqual(AesCore.shift_rows(AesCore.inv_shift_rows(state)), state)

    def test_mix_columns_known_column(self) -> None:
        state: list[int] = [0xDB, 0x13, 0x53, 0x45] * 4
        self.assertEqual(AesCore.mix_columns(state), [0x8E, 0x4D, 0xA1, 0xBC] * 4)

    def test_inv_mix_columns_inverts(self) -> None:
        state: list[int] = list(os.urandom(16))
        self.assertEqual(AesCore.inv_mix_columns(AesCore.mix_columns(state)), state)

    def test_add_round_key(self) -> None:
        self.assertEqual(AesCore.add_round_key([1, 2, 3], [1, 0, 2]), [0, 2, 1])


class TestKeyExpansion(unittest.TestCase):
    def test_round_counts(self) -> None:
        for bits, rounds in ((128, 10), (192, 12), (256, 14)):
            key: bytes = bytes.fromhex(FIPS_VECTORS[bits][0])
            with self.subTest(bits=bits):
                core = AesCore(key)
                self.assertEqual(core.nr, rounds)
                self.assertEqual(len(core.round_keys), rounds + 1)

    def test_first_round_key_is_the_key(self) -> None:
        key: bytes = bytes.fromhex(FIPS_APPENDIX_B[0])
        self.assertEqual(bytes(AesCore(key).round_keys[0]), key)

    def test_last_round_key_fips_a1(self) -> None:
        # FIPS-197 appendix A.1: w[40..43]
        key: bytes = bytes.fromhex(FIPS_APPENDIX_B[0])
        self.assertEqual(
            bytes(AesCore(key).round_keys[10]).hex(), "d014f9a8c9ee2589e13f0cc8b6630ca6"
        )

    def test_invalid_key_size(self) -> None:
        for size in (0, 8, 15, 17, 31, 33):
            with self.subTest(size=size), self.assertRaises(MyPgpError):
                AesCore(bytes(size))


class TestEncryptDecrypt(unittest.TestCase):
    def test_fips_appendix_b(self) -> None:
        key, plain, ciphered = (bytes.fromhex(v) for v in FIPS_APPENDIX_B)
        core = AesCore(key)
        self.assertEqual(core.encrypt_block(plain), ciphered)
        self.assertEqual(core.decrypt_block(ciphered), plain)

    def test_fips_appendix_c(self) -> None:
        plain: bytes = bytes.fromhex(FIPS_PLAINTEXT)
        for bits, (key_hex, ciphered_hex) in FIPS_VECTORS.items():
            core = AesCore(bytes.fromhex(key_hex))
            with self.subTest(bits=bits):
                self.assertEqual(core.encrypt_block(plain).hex(), ciphered_hex)
                self.assertEqual(core.decrypt_block(bytes.fromhex(ciphered_hex)), plain)

    def test_random_round_trips(self) -> None:
        for size in (16, 24, 32):
            for _ in range(10):
                key, block = os.urandom(size), os.urandom(16)
                with self.subTest(key=key.hex(), block=block.hex()):
                    core = AesCore(key)
                    self.assertEqual(core.decrypt_block(core.encrypt_block(block)), block)

    def test_invalid_block_size(self) -> None:
        core = AesCore(bytes(16))
        for size in (0, 15, 17, 32):
            with self.subTest(size=size):
                with self.assertRaises(MyPgpError):
                    core.encrypt_block(bytes(size))
                with self.assertRaises(MyPgpError):
                    core.decrypt_block(bytes(size))


if __name__ == "__main__":
    unittest.main()
