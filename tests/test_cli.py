from __future__ import annotations

import unittest

from cli import Args
from errors import MyPgpError


class TestValidArguments(unittest.TestCase):
    def test_cipher(self) -> None:
        args = Args(["xor", "-c", "6b6579"])
        self.assertEqual((args.system, args.mode, args.key, args.block), ("xor", "-c", "6b6579", False))

    def test_decipher_with_block(self) -> None:
        args = Args(["aes", "-d", "-b", "00" * 16])
        self.assertEqual((args.system, args.mode, args.block), ("aes", "-d", True))

    def test_block_anywhere_after_the_mode(self) -> None:
        for argv in (["xor", "-c", "-b", "6b"], ["xor", "-c", "6b", "-b"]):
            with self.subTest(argv=argv):
                args = Args(argv)
                self.assertEqual((args.mode, args.key, args.block), ("-c", "6b", True))

    def test_key_may_start_with_a_dash(self) -> None:
        self.assertEqual(Args(["rsa", "-c", "-19bb"]).key, "-19bb")
        self.assertEqual(Args(["xor", "-c", "-b", "-b"]).key, "-b")

    def test_generate_with_block(self) -> None:
        args = Args(["rsa", "-g", "d3", "e3", "-b"])
        self.assertEqual((args.p, args.q, args.block), ("d3", "e3", True))

    def test_generate_ignores_signature_flag(self) -> None:
        args = Args(["rsa", "-g", "d3", "e3", "-s"])
        self.assertEqual((args.p, args.q), ("d3", "e3"))

    def test_primes_are_not_checked_by_the_parser(self) -> None:
        self.assertEqual(Args(["rsa", "-g", "zz", " e3"]).p, "zz")

    def test_generate(self) -> None:
        args = Args(["rsa", "-g", "d3", "e3"])
        self.assertEqual((args.mode, args.p, args.q, args.key), ("-g", "d3", "e3", None))

    def test_every_system_is_known(self) -> None:
        for system in ("xor", "aes", "rsa", "pgp-xor", "pgp-aes", "elgamal", "dh"):
            with self.subTest(system=system):
                self.assertEqual(Args([system, "-c", "00"]).system, system)

    def test_signature(self) -> None:
        for system in ("rsa", "pgp-xor", "pgp-aes"):
            for argv in ([system, "-c", "-s", "k"], [system, "-d", "k", "-s"], [system, "-c", "-b", "-s", "k"]):
                with self.subTest(argv=argv):
                    args = Args(argv)
                    self.assertEqual((args.signed, args.key), (True, "k"))
        self.assertFalse(Args(["rsa", "-c", "k"]).signed)

    def test_padding(self) -> None:
        cases = (
            (["xor", "-c", "-p", "6b"], "oaep"),
            (["aes", "-d", "6b", "-p"], "oaep"),
            (["rsa", "-c", "-p", "k"], "oaep"),
            (["rsa", "-c", "-p", "oaep", "k"], "oaep"),
            (["rsa", "-d", "k", "-p", "pkcs1"], "pkcs1"),
            (["pgp-aes", "-c", "-p", "pkcs1", "-s", "-b", "k"], "pkcs1"),
            (["rsa", "-c", "k"], None),
        )
        for argv, padding in cases:
            with self.subTest(argv=argv):
                args = Args(argv)
                self.assertEqual((args.padding, args.key), (padding, "k" if "k" in argv else "6b"))

    def test_generate_random(self) -> None:
        for argv, bits in ((["rsa", "-g", "-r"], None), (["rsa", "-g", "-r", "1024"], 1024),
                           (["elgamal", "-g", "-r", "256"], 256), (["elgamal", "-g", "-r", "-b"], None)):
            with self.subTest(argv=argv):
                args = Args(argv)
                self.assertEqual((args.random, args.bits, args.p, args.q), (True, bits, None, None))

    def test_generate_elgamal(self) -> None:
        args = Args(["elgamal", "-g", "070001", "d204"])
        self.assertEqual((args.p, args.q, args.random), ("070001", "d204", False))

    def test_generate_dh(self) -> None:
        self.assertEqual(Args(["dh", "-g", "070001", "d204"]).p, "070001")
        self.assertTrue(Args(["dh", "-g", "-r"]).random)

    def test_operation(self) -> None:
        cases = (
            (["aes", "-c", "-m", "cbc", "k"], "cbc"),
            (["aes", "-d", "k", "-m", "ctr"], "ctr"),
            (["pgp-aes", "-c", "-p", "-m", "ctr", "-s", "k"], "ctr"),
            (["aes", "-c", "-b", "-m", "ecb", "k"], "ecb"),
            (["aes", "-c", "k"], "ecb"),
        )
        for argv, operation in cases:
            with self.subTest(argv=argv):
                args = Args(argv)
                self.assertEqual((args.operation, args.key), (operation, "k"))

    def test_authenticated(self) -> None:
        for system in ("xor", "aes", "pgp-xor", "pgp-aes"):
            for argv in ([system, "-c", "-a", "k"], [system, "-d", "k", "-a"]):
                with self.subTest(argv=argv):
                    args = Args(argv)
                    self.assertEqual((args.authenticated, args.key), (True, "k"))
        self.assertFalse(Args(["aes", "-c", "k"]).authenticated)

    def test_random_key(self) -> None:
        for argv in (["pgp-xor", "-c", "-k", "k"], ["pgp-aes", "-c", "k", "-k", "-s", "-b"]):
            with self.subTest(argv=argv):
                args = Args(argv)
                self.assertEqual((args.random_key, args.key), (True, "k"))

    def test_only_the_options_given_are_passed_on(self) -> None:
        self.assertEqual(Args(["aes", "-c", "k"]).options(), {})
        self.assertEqual(Args(["rsa", "-c", "-p", "-s", "k"]).options(), {})
        self.assertEqual(
            Args(["pgp-aes", "-c", "-m", "cbc", "-a", "-k", "k"]).options(),
            {"operation": "cbc", "authenticated": True, "random_key": True},
        )


class TestInvalidArguments(unittest.TestCase):
    def assert_invalid(self, argv: list[str]) -> None:
        with self.subTest(argv=argv), self.assertRaises(MyPgpError):
            Args(argv)

    def test_no_arguments(self) -> None:
        self.assert_invalid([])

    def test_mode_must_follow_the_system(self) -> None:
        for argv in (["xor", "-b", "-c", "6b"], ["xor", "6b", "-c"], ["xor", "6b", "-b", "-c"]):
            self.assert_invalid(argv)

    def test_unknown_system(self) -> None:
        for argv in (["foo", "-c", "6b"], ["-xor", "-c", "6b"], ["XOR", "-c", "6b"], ["-c", "xor", "6b"]):
            self.assert_invalid(argv)

    def test_missing_mode(self) -> None:
        self.assert_invalid(["xor"])
        self.assert_invalid(["xor", "6b"])
        self.assert_invalid(["xor", "-b", "6b"])

    def test_two_modes(self) -> None:
        self.assert_invalid(["xor", "-c", "-d", "6b"])
        self.assert_invalid(["xor", "-c", "-c", "6b"])

    def test_missing_key(self) -> None:
        self.assert_invalid(["xor", "-c"])
        self.assert_invalid(["aes", "-d", "-b"])
        self.assert_invalid(["xor", "-c", ""])

    def test_too_many_arguments(self) -> None:
        self.assert_invalid(["xor", "-c", "6b", "6c"])

    def test_unknown_option_is_an_extra_argument(self) -> None:
        # After the mode, "-z" is read as the key, so "6b" is one argument too many
        for option in ("-z", "-h", "--cipher", "-"):
            self.assert_invalid(["xor", "-c", option, "6b"])
        self.assert_invalid(["xor", "-x", "6b"])

    def test_block_twice(self) -> None:
        self.assert_invalid(["xor", "-c", "-b", "-b", "6b"])

    def test_generate_only_for_rsa_and_elgamal(self) -> None:
        for system in ("xor", "aes", "pgp-xor", "pgp-aes"):
            self.assert_invalid([system, "-g", "d3", "e3"])

    def test_generate_needs_two_numbers(self) -> None:
        self.assert_invalid(["rsa", "-g"])
        self.assert_invalid(["rsa", "-g", "d3"])
        self.assert_invalid(["rsa", "-g", "-b"])
        self.assert_invalid(["rsa", "-g", "-b", "d3", "e3"])
        self.assert_invalid(["rsa", "-g", "d3", "-b", "e3"])

    def test_generate_rejects_key(self) -> None:
        self.assert_invalid(["rsa", "-g", "d3", "e3", "010001-19bb"])

    def test_signature_only_for_rsa_and_pgp(self) -> None:
        for argv in (["xor", "-c", "-s", "6b"], ["aes", "-d", "6b", "-s"], ["elgamal", "-c", "-s", "01-02-03"],
                     ["elgamal", "-g", "-r", "-s"], ["rsa", "-c", "-s", "-s", "k"]):
            self.assert_invalid(argv)

    def test_invalid_padding(self) -> None:
        for argv in (["xor", "-c", "-p", "oaep", "6b"], ["aes", "-c", "-p", "pkcs1", "6b"],
                     ["elgamal", "-c", "-p", "k"], ["rsa", "-g", "d3", "e3", "-p"], ["rsa", "-c", "-p"],
                     ["rsa", "-c", "-p", "pkcs7", "k"], ["rsa", "-c", "-p", "-p", "k"]):
            self.assert_invalid(argv)

    def test_invalid_operation(self) -> None:
        for argv in (["xor", "-c", "-m", "cbc", "6b"], ["pgp-xor", "-c", "-m", "cbc", "k"],
                     ["rsa", "-c", "-m", "cbc", "k"], ["dh", "-c", "-m", "ctr", "k"], ["aes", "-c", "-m", "k"],
                     ["aes", "-c", "-m", "cfb", "k"], ["aes", "-c", "k", "-m"], ["aes", "-c", "-m", "-m", "cbc", "k"],
                     ["aes", "-c", "-b", "-m", "cbc", "k"], ["aes", "-c", "-m", "ctr", "-p", "k"],
                     ["aes", "-c", "-m", "cbc", "-m", "ctr", "k"]):
            self.assert_invalid(argv)

    def test_invalid_authentication(self) -> None:
        for argv in (["rsa", "-c", "-a", "k"], ["elgamal", "-c", "-a", "k"], ["dh", "-d", "-a", "k"],
                     ["rsa", "-g", "d3", "e3", "-a"], ["aes", "-c", "-b", "-a", "k"], ["xor", "-c", "-a", "-a", "6b"]):
            self.assert_invalid(argv)

    def test_invalid_random_key(self) -> None:
        for argv in (["xor", "-c", "-k", "6b"], ["aes", "-c", "-k", "k"], ["rsa", "-c", "-k", "k"],
                     ["dh", "-c", "-k", "k"], ["pgp-aes", "-d", "-k", "k"], ["rsa", "-g", "-r", "-k"]):
            self.assert_invalid(argv)

    def test_invalid_random_generation(self) -> None:
        for argv in (["rsa", "-c", "-r", "k"], ["rsa", "-g", "-r", "1024", "k"], ["rsa", "-g", "d3", "-r"],
                     ["xor", "-g", "-r"], ["rsa", "-g", "-r", "12", "34"]):
            self.assert_invalid(argv)


if __name__ == "__main__":
    unittest.main()
