"""Option -s: RSASSA-PKCS1-v1_5 signature (SHA-256) of the ciphered message.

  rsa  -c -s  key = RECIPIENT_PUBLIC:SIGNER_PRIVATE      out = C, then signature
  rsa  -d -s  key = RECIPIENT_PRIVATE:SIGNER_PUBLIC      in  = C, then signature
  pgp  -c -s  key = SYM:RECIPIENT_PUBLIC:SIGNER_PRIVATE  out = CK, CM, then signature
  pgp  -d -s  key = CK:RECIPIENT_PRIVATE:SIGNER_PUBLIC   in  = CM, then signature

Signatures are deterministic, so they are compared with an oracle built on hashlib and pow.
"""
from __future__ import annotations

import unittest

from errors import MyPgpError
from systems.pgp import Pgp, PgpAes, PgpXor
from systems.rsa import Rsa, RsaKey, split_signature
from tests.helpers import BIG_RSA_KEYS, RSA_KEYS, SIGNER_KEYS, SMALL_RSA_KEYS, le_hex, le_int, rsa_sign_oracle

XOR_KEY: str = "6b6579"
AES_KEY: str = bytes(range(1, 17)).hex()


def lines(output: bytes) -> list[str]:
    return output.decode().splitlines()


class TestRsaKeySignature(unittest.TestCase):
    def test_sign_matches_oracle(self) -> None:
        for keys in (RSA_KEYS, SIGNER_KEYS, BIG_RSA_KEYS):
            with self.subTest(n=keys.n.bit_length()):
                self.assertEqual(RsaKey.parse(keys.private).sign(b"hello"), rsa_sign_oracle(b"hello", keys))

    def test_verify(self) -> None:
        signature: int = rsa_sign_oracle(b"hello", SIGNER_KEYS)
        RsaKey.parse(SIGNER_KEYS.public).verify(b"hello", signature)
        for data, sig in ((b"hellp", signature), (b"hello", signature + 1), (b"hello", signature + SIGNER_KEYS.n)):
            with self.subTest(data=data), self.assertRaises(MyPgpError):
                RsaKey.parse(SIGNER_KEYS.public).verify(data, sig)

    def test_signer_key_too_small(self) -> None:
        with self.assertRaises(MyPgpError):
            RsaKey.parse(SMALL_RSA_KEYS.private).sign(b"hello")
        with self.assertRaises(MyPgpError):
            Rsa(f"{RSA_KEYS.public}:{SMALL_RSA_KEYS.private}", False, signed=True).check_key("-c")

    def test_split_signature(self) -> None:
        self.assertEqual(split_signature(b"abcd\n0102"), (b"abcd", 0x201))
        self.assertEqual(split_signature(b"ab\ncd\n0102\n\n"), (b"ab\ncd", 0x201))
        for data in (b"abcd", b"", b"\n0102", b"abcd\nzz"):
            with self.subTest(data=data), self.assertRaises(MyPgpError):
                split_signature(data)


class TestRsaSignature(unittest.TestCase):
    SIGNED_CIPHER: str = f"{RSA_KEYS.public}:{SIGNER_KEYS.private}"
    SIGNED_DECIPHER: str = f"{RSA_KEYS.private}:{SIGNER_KEYS.public}"

    def test_output_is_ciphered_then_signature(self) -> None:
        output: bytes = Rsa(self.SIGNED_CIPHER, False, signed=True).cipher(b"WF")
        c: int = pow(le_int("5746"), RSA_KEYS.e, RSA_KEYS.n)
        signature: int = rsa_sign_oracle(bytes.fromhex(le_hex(c)), SIGNER_KEYS)
        self.assertEqual(lines(output), [le_hex(c), le_hex(signature)])

    def test_round_trip(self) -> None:
        output: bytes = Rsa(self.SIGNED_CIPHER, False, signed=True).cipher(b"The night is dark")
        self.assertEqual(Rsa(self.SIGNED_DECIPHER, False, signed=True).decipher(output), b"The night is dark\n")

    def test_round_trip_with_padding(self) -> None:
        output: bytes = Rsa(self.SIGNED_CIPHER, False, "pkcs1", True).cipher(b"hi\x00")
        self.assertEqual(Rsa(self.SIGNED_DECIPHER, False, "pkcs1", True).decipher(output), b"hi\x00\n")

    def test_tampered_ciphered_message_is_rejected(self) -> None:
        c, signature = lines(Rsa(self.SIGNED_CIPHER, False, signed=True).cipher(b"WF"))
        tampered: str = le_hex(le_int(c) + 1)
        with self.assertRaises(MyPgpError):
            Rsa(self.SIGNED_DECIPHER, False, signed=True).decipher(f"{tampered}\n{signature}".encode())

    def test_wrong_signer_is_rejected(self) -> None:
        output: bytes = Rsa(self.SIGNED_CIPHER, False, signed=True).cipher(b"WF")
        with self.assertRaises(MyPgpError):
            Rsa(f"{RSA_KEYS.private}:{RSA_KEYS.public}", False, signed=True).decipher(output)

    def test_missing_signature(self) -> None:
        with self.assertRaises(MyPgpError):
            Rsa(self.SIGNED_DECIPHER, False, signed=True).decipher(b"8f84\n")

    def test_key_format(self) -> None:
        for key in (RSA_KEYS.public, f"{RSA_KEYS.public}:", f"{RSA_KEYS.public}:{RSA_KEYS.private}:{RSA_KEYS.public}"):
            with self.subTest(key=key[:12]), self.assertRaises(MyPgpError):
                Rsa(key, False, signed=True)


class TestPgpSignature(unittest.TestCase):
    def cipher(self, system: type, sym_key: str, message: bytes, block: bool = False) -> list[str]:
        return lines(system(f"{sym_key}:{RSA_KEYS.public}:{SIGNER_KEYS.private}", block, signed=True).cipher(message))

    def decipher(self, system: type, ciphered_key: str, body: str, block: bool = False) -> bytes:
        return system(f"{ciphered_key}:{RSA_KEYS.private}:{SIGNER_KEYS.public}", block, signed=True).decipher(
            body.encode()
        )

    def test_output_is_unsigned_output_then_signature(self) -> None:
        signed: list[str] = self.cipher(PgpAes, AES_KEY, b"All men must die", True)
        unsigned: list[str] = lines(PgpAes(f"{AES_KEY}:{RSA_KEYS.public}", True).cipher(b"All men must die"))
        self.assertEqual(signed[:2], unsigned)
        self.assertEqual(len(signed), 3)

    def test_signature_covers_key_and_message(self) -> None:
        ck, cm, signature = self.cipher(PgpXor, XOR_KEY, b"hello")
        key_bytes: bytes = bytes.fromhex(ck)
        data: bytes = len(key_bytes).to_bytes(4, "big") + key_bytes + bytes.fromhex(cm)
        self.assertEqual(signature, le_hex(rsa_sign_oracle(data, SIGNER_KEYS)))
        self.assertEqual(Pgp.signed_data(le_int(ck), bytes.fromhex(cm)), data)

    def test_round_trips(self) -> None:
        for system, sym_key in ((PgpXor, XOR_KEY), (PgpAes, AES_KEY)):
            # 48 bytes: whole blocks for both keys, so no 00 padding comes back in stream mode
            for block, message in ((False, b"x" * 48), (True, bytes(len(bytes.fromhex(sym_key))))):
                ck, cm, signature = self.cipher(system, sym_key, message, block)
                with self.subTest(system=system.name, block=block):
                    self.assertEqual(self.decipher(system, ck, f"{cm}\n{signature}\n", block), message + b"\n")

    def test_tampering_is_rejected(self) -> None:
        ck, cm, signature = self.cipher(PgpAes, AES_KEY, b"hello")
        other_cm: str = ("ff" if cm[:2] != "ff" else "00") + cm[2:]
        other_ck: str = le_hex(le_int(ck) ^ 1)
        for key, body in ((ck, f"{other_cm}\n{signature}"), (other_ck, f"{cm}\n{signature}"), (ck, cm)):
            with self.subTest(key=key[:8], body=body[:8]), self.assertRaises(MyPgpError):
                self.decipher(PgpAes, key, body)

    def test_key_format(self) -> None:
        for key in (f"{AES_KEY}:{RSA_KEYS.public}", f"{AES_KEY}:{RSA_KEYS.public}:{SIGNER_KEYS.private}:x"):
            with self.subTest(key=key[-6:]), self.assertRaises(MyPgpError):
                PgpAes(key, False, signed=True)
        with self.assertRaises(MyPgpError):
            PgpAes(f"{AES_KEY}:{RSA_KEYS.public}:{SIGNER_KEYS.private}", False)


if __name__ == "__main__":
    unittest.main()
