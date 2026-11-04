"""Every example given in the subject (my_PGP v2.3), checked byte for byte."""
from __future__ import annotations

import unittest

from tests.helpers import Result, le_hex, le_int, run

XOR_KEY: str = "576861742069732064656164206d6179206e6576657220646965"
XOR_CIPHERED: str = "20070f2700071c6a4449060a490515164e4e12190b190011063c"
AES_KEY: str = "57696e74657220697320636f6d696e67"
AES_CIPHERED: str = "744ce22c385958348f0df26eceb62eef"

P_256: str = "4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1"
Q_256: str = "bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb"
MODULUS: str = (
    "c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
    "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
)
PUBLIC: str = "010001-" + MODULUS
PRIVATE: str = (
    "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a"
    "11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-" + MODULUS
)
RSA_CIPHERED: str = (
    "445b349e7318ad6af16b0bbb718be88ba1c41751f95751cd58857f88fe31f970"
    "405c6ec3f16d79172543bf4e571b5596d212f3e79cd08ef14abd244e325b80"
)
PGP_AES_CIPHERED_KEY: str = (
    "97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f"
    "9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d"
)


class SubjectTestCase(unittest.TestCase):
    def assert_output(self, result: Result, stdout: str) -> None:
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.code, 0)
        self.assertEqual(result.stdout, stdout.encode())


class TestSubjectXor(SubjectTestCase):
    def test_cipher(self) -> None:
        result = run(["xor", "-c", "-b", XOR_KEY], b"You know nothing, Jon Snow\n")
        self.assert_output(result, XOR_CIPHERED + "\n")

    def test_decipher(self) -> None:
        result = run(["xor", "-d", "-b", XOR_KEY], (XOR_CIPHERED + "\n").encode())
        self.assert_output(result, "You know nothing, Jon Snow\n")


class TestSubjectAes(SubjectTestCase):
    def test_cipher(self) -> None:
        result = run(["aes", "-c", "-b", AES_KEY], b"All men must die\n")
        self.assert_output(result, AES_CIPHERED + "\n")

    def test_decipher(self) -> None:
        result = run(["aes", "-d", "-b", AES_KEY], (AES_CIPHERED + "\n").encode())
        self.assert_output(result, "All men must die\n")


class TestSubjectRsa(SubjectTestCase):
    def test_generate_small(self) -> None:
        self.assert_output(run(["rsa", "-g", "d3", "e3"]), "public key: 0101-19bb\nprivate key: 9d5b-19bb\n")

    def test_cipher_small(self) -> None:
        self.assert_output(run(["rsa", "-c", "0101-19bb"], b"WF\n"), "8f84\n")

    def test_decipher_small(self) -> None:
        self.assert_output(run(["rsa", "-d", "9d5b-19bb"], b"8f84\n"), "WF\n")

    def test_generate_large(self) -> None:
        self.assert_output(
            run(["rsa", "-g", P_256, Q_256]), f"public key: {PUBLIC}\nprivate key: {PRIVATE}\n"
        )

    def test_cipher_large(self) -> None:
        result = run(["rsa", "-c", PUBLIC], b"The night is dark and full of terrors\n")
        self.assert_output(result, RSA_CIPHERED + "\n")

    def test_decipher_large(self) -> None:
        result = run(["rsa", "-d", PRIVATE], (RSA_CIPHERED + "\n").encode())
        self.assert_output(result, "The night is dark and full of terrors\n")


class TestSubjectPgp(SubjectTestCase):
    def test_pgp_aes_cipher(self) -> None:
        result = run(["pgp-aes", "-c", "-b", f"{AES_KEY}:{PUBLIC}"], b"All men must die\n")
        self.assert_output(result, f"{PGP_AES_CIPHERED_KEY}\n{AES_CIPHERED}\n")

    def test_pgp_aes_decipher(self) -> None:
        result = run(
            ["pgp-aes", "-d", "-b", f"{PGP_AES_CIPHERED_KEY}:{PRIVATE}"], (AES_CIPHERED + "\n").encode()
        )
        self.assert_output(result, "All men must die\n")

    def test_pgp_xor_cipher(self) -> None:
        """No pgp-xor example in the subject: built from the xor and rsa examples."""
        e, n = (le_int(part) for part in PUBLIC.split("-"))
        ciphered_key: str = le_hex(pow(le_int(XOR_KEY), e, n))
        result = run(["pgp-xor", "-c", "-b", f"{XOR_KEY}:{PUBLIC}"], b"You know nothing, Jon Snow\n")
        self.assert_output(result, f"{ciphered_key}\n{XOR_CIPHERED}\n")

    def test_pgp_xor_decipher(self) -> None:
        e, n = (le_int(part) for part in PUBLIC.split("-"))
        ciphered_key: str = le_hex(pow(le_int(XOR_KEY), e, n))
        result = run(["pgp-xor", "-d", "-b", f"{ciphered_key}:{PRIVATE}"], (XOR_CIPHERED + "\n").encode())
        self.assert_output(result, "You know nothing, Jon Snow\n")

    def test_pgp_xor_stream_round_trip(self) -> None:
        message: bytes = b"You know nothing, Jon Snow\nWinter is coming\n"
        ciphered = run(["pgp-xor", "-c", f"{XOR_KEY}:{PUBLIC}"], message)
        first_line, _, rest = ciphered.stdout.partition(b"\n")
        # The trailing "\n" is not ciphered, and the 00 padding comes back on decipher
        expected: str = "You know nothing, Jon Snow\nWinter is coming" + "\x00" * 9 + "\n"
        self.assert_output(run(["pgp-xor", "-d", f"{first_line.decode()}:{PRIVATE}"], rest), expected)


class TestSubjectAppendixPrimes(SubjectTestCase):
    def test_every_pair_of_appendix_primes_round_trips(self) -> None:
        pairs: tuple[tuple[str, str], ...] = (
            ("e9", "f1"),
            ("13d3c01d", "0b1e8a1e"),
            ("d3dd082f", "0bfe6c0d"),
            (
                "d5da1a8d443812956185f9fe2d8696ea4959d3415967c7a8c5fec34bf7dd53e1",
                "4fbd36c46bd3fa40ebcef3447a4e2f2f16a6cee884bf889fd58ec5bca6024fe1",
            ),
            (
                "d7c9d58c694fe7ad5d77d888c98d71e7f6a58b4f4dc90582668fd28c0bc20f51"
                "c667ba7b70cb94842006eb5b223065346f7a6bb307ef572fee882c8ef420410b"
                "8b8fa8278ae6a300e63123b28ba1d47259bc308827fcd509585bcee1d98b461f"
                "9eff9c20559540b8c0d6036eff7caf0107d935ecefd5faab87b802bf74c041c8",
                "e9dfe6b53248c4dc0f391fdda5694bd9f68e111dac5e921a942a157ec92431dc"
                "4833e1a327d36cebcc4ac9b76f2ac2a643db8a04c14963759a800f75915de3ff"
                "beccf86118923b388b352f7e3d20edfd5bb6609fd0b6416da6a56050b000ae9e"
                "14065f06f46ccfaa84c755689e8d95525bb1de8b8a43d380f4db68baac92e0bf",
            ),
        )
        for p, q in pairs:
            with self.subTest(p=p, q=q):
                lines: list[str] = run(["rsa", "-g", p, q]).stdout.decode().splitlines()
                public, private = (line.split(": ", 1)[1] for line in lines)
                ciphered = run(["rsa", "-c", public], b"A\n")
                self.assert_output(run(["rsa", "-d", private], ciphered.stdout), "A\n")


if __name__ == "__main__":
    unittest.main()
