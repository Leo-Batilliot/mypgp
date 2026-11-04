"""End-to-end tests: run the program like the user (or the moulinette) does.

By default the program is run with `python3 src/`. Set MY_PGP_BIN=./my_pgp
(done by `make tests_run`) to test the built binary instead.
"""
from __future__ import annotations

import os
import unittest

from tests.helpers import (
    BIG_RSA_KEYS,
    FIPS_PLAINTEXT,
    FIPS_VECTORS,
    P_HEX,
    Q_HEX,
    RSA_KEYS,
    SAFE_PRIME,
    SIGNER_KEYS,
    SMALL_P_HEX,
    SMALL_Q_HEX,
    SMALL_RSA_KEYS,
    Result,
    is_probable_prime,
    le_hex,
    le_int,
    rsa_oracle,
    run,
    word_reverse,
    xor_block_oracle,
    xor_stream_decipher_oracle,
    xor_stream_oracle,
    zero_pad,
)

XOR_KEY: str = "6b6579"
AES_KEY: str = bytes(range(1, 17)).hex()


class FunctionalTestCase(unittest.TestCase):
    def assert_success(self, result: Result, stdout: bytes) -> None:
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.code, 0)
        self.assertEqual(result.stdout, stdout)

    def assert_error(self, result: Result) -> None:
        self.assertEqual(result.code, 84, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertTrue(result.stderr.startswith(b"my_pgp: "), result.stderr)


class TestHelpAndErrors(FunctionalTestCase):
    def test_help(self) -> None:
        result = run(["-h"])
        self.assertEqual(result.code, 0)
        self.assertTrue(result.stdout.startswith(b"USAGE"))
        for system in (b"xor", b"aes", b"rsa", b"pgp-xor", b"pgp-aes"):
            self.assertIn(system, result.stdout)

    def test_invalid_command_lines(self) -> None:
        cases: tuple[list[str], ...] = (
            [],
            ["foo", "-c", XOR_KEY],
            ["xor"],
            ["xor", "-c"],
            ["xor", XOR_KEY],
            ["xor", "-c", "-d", XOR_KEY],
            ["xor", "-c", "-z", XOR_KEY],
            ["xor", "-c", XOR_KEY, "extra"],
            ["xor", "-c", "-b", "-b", XOR_KEY],
            ["xor", "-g", "d3", "e3"],
            ["rsa", "-g", "d3"],
            ["xor", "-b", "-c", XOR_KEY],
            ["xor", XOR_KEY, "-c"],
            ["xor", "-c", "-s", XOR_KEY],
            ["rsa", "-c", "-s", RSA_KEYS.public],
            ["rsa", "-g", "zz", "e3"],
            ["rsa", "-g", "02", "03"],
            ["-h", "xor"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                self.assert_error(run(argv, b"hello"))

    def test_invalid_keys(self) -> None:
        cases: tuple[list[str], ...] = (
            ["xor", "-c", "zz"],
            ["xor", "-c", "6b6"],
            ["aes", "-c", "00" * 15],
            ["aes", "-c", "00" * 33],
            ["rsa", "-c", "010001"],
            ["rsa", "-c", "010001-1"],
            ["xor", "-c", ""],
            ["xor", "-c", "  "],
            ["pgp-xor", "-c", XOR_KEY],
            ["pgp-aes", "-c", f"{AES_KEY}:010001"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                self.assert_error(run(argv, b"hello"))

    def test_invalid_ciphered_input(self) -> None:
        cases: tuple[tuple[list[str], bytes], ...] = (
            (["xor", "-d", XOR_KEY], b"not hex\n"),
            (["xor", "-d", XOR_KEY], b"080\n"),
            (["xor", "-d", XOR_KEY], b"0807 1 8\n"),
            (["xor", "-d", "-b", XOR_KEY], b"08071800\n"),
            (["xor", "-d", "-b", XOR_KEY], b""),
            (["aes", "-d", "-b", AES_KEY], b"00" * 15 + b"\n"),
            (["rsa", "-d", RSA_KEYS.private], b"xyz\n"),
            (["xor", "-d", XOR_KEY], "é".encode()),
        )
        for argv, stdin in cases:
            with self.subTest(argv=argv, stdin=stdin):
                self.assert_error(run(argv, stdin))

    def test_block_size_mismatch(self) -> None:
        self.assert_error(run(["xor", "-c", "-b", XOR_KEY], b"abcd"))
        self.assert_error(run(["aes", "-c", "-b", AES_KEY], b"too short"))


class TestXor(FunctionalTestCase):
    def test_cipher_stream(self) -> None:
        message: bytes = b"I love spinach\n"
        expected: bytes = xor_stream_oracle(message[:-1], b"key").hex().encode() + b"\n"
        self.assert_success(run(["xor", "-c", XOR_KEY], message), expected)

    def test_stream_ignores_only_one_trailing_newline(self) -> None:
        for message in (b"abc\n\n", b"abc\r\n", b"\n"):
            expected: bytes = xor_stream_oracle(message[:-1], b"key").hex().encode() + b"\n"
            with self.subTest(message=message):
                self.assert_success(run(["xor", "-c", XOR_KEY], message), expected)

    def test_cipher_block(self) -> None:
        self.assert_success(run(["xor", "-c", "-b", XOR_KEY], b"abc"), b"080718\n")

    def test_block_mode_ignores_one_trailing_newline(self) -> None:
        self.assert_success(run(["xor", "-c", "-b", XOR_KEY], b"abc\n"), b"080718\n")

    def test_decipher_block(self) -> None:
        self.assert_success(run(["xor", "-d", "-b", XOR_KEY], b"080718\n"), b"abc\n")

    def test_decipher_block_uppercase_hex(self) -> None:
        self.assert_success(run(["xor", "-d", "-b", XOR_KEY], b"080718\n".upper()), b"abc\n")

    def test_stream_keeps_inner_newlines_and_padding(self) -> None:
        message: bytes = b"line 1\nline 2\n"
        ciphered = run(["xor", "-c", XOR_KEY], message)
        self.assert_success(run(["xor", "-d", XOR_KEY], ciphered.stdout), b"line 1\nline 2\x00\x00\n")

    def test_decipher_stream_partial_block(self) -> None:
        self.assert_success(run(["xor", "-d", XOR_KEY], b"08071800\n"), b"abcyek\n")

    def test_decipher_hex_with_whitespace(self) -> None:
        for stdin in (b" 080718 \n", b"0807 18\n", b"0807\n18\n", b"080718"):
            with self.subTest(stdin=stdin):
                self.assert_success(run(["xor", "-d", XOR_KEY], stdin), b"abc\n")

    def test_binary_round_trip(self) -> None:
        message: bytes = os.urandom(256).replace(b"\n", b"\x01")
        key: str = os.urandom(16).hex()
        ciphered = run(["xor", "-c", key], message)
        self.assert_success(run(["xor", "-d", key], ciphered.stdout), message + b"\n")

    def test_block_matches_oracle(self) -> None:
        key, message = os.urandom(32), os.urandom(31) + b"x"  # no trailing "\n" (stripped in -b mode)
        expected: bytes = xor_block_oracle(message, key).hex().encode() + b"\n"
        self.assert_success(run(["xor", "-c", "-b", key.hex()], message), expected)

    def test_empty_input(self) -> None:
        self.assert_success(run(["xor", "-c", XOR_KEY], b""), b"\n")
        self.assert_success(run(["xor", "-d", XOR_KEY], b""), b"\n")
        self.assert_success(run(["xor", "-d", XOR_KEY], b"\n"), b"\n")


class TestAes(FunctionalTestCase):
    def test_cipher_block_epitech_vectors(self) -> None:
        for bits, (key_hex, ciphered_hex) in FIPS_VECTORS.items():
            key: str = word_reverse(bytes.fromhex(key_hex)).hex()
            expected: bytes = word_reverse(bytes.fromhex(ciphered_hex)).hex().encode() + b"\n"
            with self.subTest(bits=bits):
                self.assert_success(run(["aes", "-c", "-b", key], bytes.fromhex(FIPS_PLAINTEXT)), expected)

    def test_decipher_block_epitech_vectors(self) -> None:
        for bits, (key_hex, ciphered_hex) in FIPS_VECTORS.items():
            key: str = word_reverse(bytes.fromhex(key_hex)).hex()
            ciphered: bytes = word_reverse(bytes.fromhex(ciphered_hex)).hex().encode() + b"\n"
            with self.subTest(bits=bits):
                self.assert_success(
                    run(["aes", "-d", "-b", key], ciphered), bytes.fromhex(FIPS_PLAINTEXT) + b"\n"
                )

    def test_stream_round_trip(self) -> None:
        message: bytes = b"All men must die.\nValar morghulis, this spans several blocks.\n"
        for size in (16, 24, 32):
            key: str = os.urandom(size).hex()
            ciphered = run(["aes", "-c", key], message)
            with self.subTest(size=size):
                self.assertEqual(ciphered.code, 0)
                self.assertEqual(len(ciphered.stdout.strip()) % 32, 0)
                self.assert_success(run(["aes", "-d", key], ciphered.stdout), zero_pad(message[:-1], 16) + b"\n")

    def test_block_round_trip(self) -> None:
        message: bytes = b"0123456789abcdef"
        ciphered = run(["aes", "-c", "-b", AES_KEY], message)
        self.assert_success(run(["aes", "-d", "-b", AES_KEY], ciphered.stdout), message + b"\n")

    def test_binary_round_trip(self) -> None:
        message: bytes = os.urandom(300).replace(b"\n", b"\x01")
        ciphered = run(["aes", "-c", AES_KEY], message)
        self.assert_success(run(["aes", "-d", AES_KEY], ciphered.stdout), zero_pad(message, 16) + b"\n")

    def test_decipher_stream_partial_block(self) -> None:
        full = run(["aes", "-d", AES_KEY], b"00" * 32 + b"\n")
        self.assert_success(run(["aes", "-d", AES_KEY], b"00" * 20 + b"\n"), full.stdout)


class TestRsa(FunctionalTestCase):
    def test_generate_small_primes(self) -> None:
        keys = rsa_oracle(le_int(SMALL_P_HEX), le_int(SMALL_Q_HEX))
        expected: bytes = f"public key: {keys.public}\nprivate key: {keys.private}\n".encode()
        self.assert_success(run(["rsa", "-g", SMALL_P_HEX, SMALL_Q_HEX]), expected)

    def test_generate_256_bit_primes(self) -> None:
        expected: bytes = f"public key: {RSA_KEYS.public}\nprivate key: {RSA_KEYS.private}\n".encode()
        self.assert_success(run(["rsa", "-g", P_HEX, Q_HEX]), expected)

    def test_generate_ignores_stdin(self) -> None:
        self.assertEqual(run(["rsa", "-g", SMALL_P_HEX, SMALL_Q_HEX], b"ignored").code, 0)

    def test_cipher_matches_oracle(self) -> None:
        expected: int = pow(int.from_bytes(b"hello", "little"), RSA_KEYS.e, RSA_KEYS.n)
        self.assert_success(run(["rsa", "-c", RSA_KEYS.public], b"hello"), le_hex(expected).encode() + b"\n")

    def test_cipher_ignores_one_trailing_newline(self) -> None:
        self.assertEqual(
            run(["rsa", "-c", RSA_KEYS.public], b"hello\n").stdout,
            run(["rsa", "-c", RSA_KEYS.public], b"hello").stdout,
        )

    def test_generate_then_cipher_then_decipher(self) -> None:
        generated = run(["rsa", "-g", P_HEX, Q_HEX])
        lines: list[str] = generated.stdout.decode().splitlines()
        public: str = lines[0].split(": ", 1)[1]
        private: str = lines[1].split(": ", 1)[1]
        ciphered = run(["rsa", "-c", public], b"My secret message")
        self.assert_success(run(["rsa", "-d", private], ciphered.stdout), b"My secret message\n")

    def test_message_bigger_than_modulus_is_reduced(self) -> None:
        expected: int = pow(int.from_bytes(b"x" * 100, "little"), RSA_KEYS.e, RSA_KEYS.n)
        self.assert_success(run(["rsa", "-c", RSA_KEYS.public], b"x" * 100), le_hex(expected).encode() + b"\n")

    def test_generate_equal_primes(self) -> None:
        n: str = le_hex(211 * 211)
        self.assert_success(run(["rsa", "-g", "d3", "d3"]), f"public key: 11-{n}\nprivate key: ad-{n}\n".encode())

    def test_decipher_empty_input(self) -> None:
        self.assert_success(run(["rsa", "-d", RSA_KEYS.private], b""), b"\x00\n")


class TestPgp(FunctionalTestCase):
    """Decipher key = first line of the cipher output + ':' + private RSA key,
    and stdin = the rest of the cipher output."""

    def round_trip(self, system: str, sym_key: str, message: bytes, block: bool = False) -> Result:
        flags: list[str] = ["-b"] if block else []
        ciphered = run([system, "-c", *flags, f"{sym_key}:{RSA_KEYS.public}"], message)
        self.assertEqual(ciphered.code, 0, ciphered.stderr)
        first_line, _, rest = ciphered.stdout.partition(b"\n")
        return run([system, "-d", *flags, f"{first_line.decode()}:{RSA_KEYS.private}"], rest)

    def test_cipher_first_line_is_rsa_ciphered_key(self) -> None:
        result = run(["pgp-xor", "-c", f"{XOR_KEY}:{RSA_KEYS.public}"], b"hello")
        first_line: bytes = result.stdout.split(b"\n")[0]
        expected: str = le_hex(pow(le_int(XOR_KEY), RSA_KEYS.e, RSA_KEYS.n))
        self.assertEqual(first_line.decode(), expected)

    def test_pgp_xor_stream(self) -> None:
        self.assert_success(self.round_trip("pgp-xor", XOR_KEY, b"hello world\n"), b"hello world\x00\n")

    def test_pgp_xor_block(self) -> None:
        self.assert_success(self.round_trip("pgp-xor", XOR_KEY, b"abc", block=True), b"abc\n")

    def test_pgp_aes_stream(self) -> None:
        for size in (16, 24, 32):
            key: str = bytes(range(1, size + 1)).hex()
            with self.subTest(size=size):
                self.assert_success(
                    self.round_trip("pgp-aes", key, b"hello world\n"), b"hello world" + bytes(5) + b"\n"
                )

    def test_pgp_aes_block(self) -> None:
        self.assert_success(
            self.round_trip("pgp-aes", AES_KEY, b"0123456789abcdef", block=True), b"0123456789abcdef\n"
        )

    def test_pgp_xor_block_ciphered_size_mismatch(self) -> None:
        """Regression: -d -b used to pad the key to the ciphered size and exit with 0."""
        ciphered_key: str = le_hex(pow(le_int(XOR_KEY), RSA_KEYS.e, RSA_KEYS.n))
        key: str = f"{ciphered_key}:{RSA_KEYS.private}"
        for ciphered in (b"0011\n", b"0011223344\n"):
            with self.subTest(ciphered=ciphered):
                self.assert_error(run(["pgp-xor", "-d", "-b", key], ciphered))

    def test_pgp_xor_big_stream_with_one_byte_key(self) -> None:
        """Regression: one bytes object per block took ~135 bytes of memory per input byte
        (~670 MB for 5 MB with a 1-byte key): killed under a memory limit."""
        limit: int = 512 * 1024 * 1024
        message: bytes = os.urandom(5_000_000)
        ciphered = run(["pgp-xor", "-c", f"41:{RSA_KEYS.public}"], message, limit)
        self.assertEqual(ciphered.code, 0, ciphered.stderr)
        first_line, _, rest = ciphered.stdout.partition(b"\n")
        deciphered = run(["pgp-xor", "-d", f"{first_line.decode()}:{RSA_KEYS.private}"], rest, limit)
        self.assert_success(deciphered, message + b"\n")

    def test_pgp_xor_key_ending_with_zero_byte(self) -> None:
        """The trailing 00 of the key is lost through RSA: the message is deciphered
        with the shorter key, by blocks of its size (see docs/pgp.md)."""
        ciphered: bytes = xor_stream_oracle(b"abcdefg", bytes.fromhex("6b6500"))
        expected: bytes = xor_stream_decipher_oracle(ciphered, bytes.fromhex("6b65"))
        self.assert_success(self.round_trip("pgp-xor", "6b6500", b"abcdefg"), expected + b"\n")

    def test_pgp_aes_key_ending_with_zero_bytes_is_rejected(self) -> None:
        """A 32-byte key ending with 00 comes back shorter than 32 bytes: not an AES key."""
        key: str = (bytes(range(1, 26)) + bytes(7)).hex()
        self.assert_error(self.round_trip("pgp-aes", key, b"hello world"))


def generated_keys(result: Result) -> tuple[str, str]:
    public, private = (line.split(": ", 1)[1] for line in result.stdout.decode().splitlines())
    return public, private


class TestRandomKeys(FunctionalTestCase):
    def test_rsa_random_keys_work(self) -> None:
        result = run(["rsa", "-g", "-r", "512"])
        self.assertEqual((result.code, result.stderr), (0, b""))
        public, private = generated_keys(result)
        e, n = (le_int(part) for part in public.split("-"))
        self.assertEqual((e, n.bit_length()), (65537, 512))
        ciphered = run(["rsa", "-c", public], b"Winter is coming\n")
        self.assert_success(run(["rsa", "-d", private], ciphered.stdout), b"Winter is coming\n")

    def test_rsa_random_keys_differ(self) -> None:
        self.assertNotEqual(run(["rsa", "-g", "-r", "256"]).stdout, run(["rsa", "-g", "-r", "256"]).stdout)

    def test_rsa_random_default_size(self) -> None:
        public, _ = generated_keys(run(["rsa", "-g", "-r"]))
        self.assertEqual(le_int(public.split("-")[1]).bit_length(), 2048)

    def test_invalid(self) -> None:
        for argv in (["rsa", "-g", "-r", "8"], ["xor", "-g", "-r"], ["rsa", "-g", "-r", "512", "k"]):
            with self.subTest(argv=argv):
                self.assert_error(run(argv))


class TestPaddingOption(FunctionalTestCase):
    def test_symmetric_round_trips_are_exact(self) -> None:
        for system, key in (("xor", XOR_KEY), ("aes", AES_KEY)):
            for message in (b"", b"abc", b"0123456789abcdef", os.urandom(1000)):
                ciphered = run([system, "-c", "-p", key], message)
                with self.subTest(system=system, length=len(message)):
                    self.assert_success(run([system, "-d", "-p", key], ciphered.stdout), message + b"\n")

    def test_rsa_round_trips_keep_trailing_zeros(self) -> None:
        for flags, keys in ((["-p"], BIG_RSA_KEYS), (["-p", "oaep"], BIG_RSA_KEYS), (["-p", "pkcs1"], RSA_KEYS)):
            ciphered = run(["rsa", "-c", *flags, keys.public], b"WF\x00\n")
            with self.subTest(flags=flags):
                self.assert_success(run(["rsa", "-d", *flags, keys.private], ciphered.stdout), b"WF\x00\n")

    def test_pgp_round_trip(self) -> None:
        ciphered = run(["pgp-aes", "-c", "-p", "pkcs1", f"{AES_KEY}:{RSA_KEYS.public}"], b"All men must die")
        first_line, _, rest = ciphered.stdout.partition(b"\n")
        result = run(["pgp-aes", "-d", "-p", "pkcs1", f"{first_line.decode()}:{RSA_KEYS.private}"], rest)
        self.assert_success(result, b"All men must die\n")

    def test_errors(self) -> None:
        cases: tuple[tuple[list[str], bytes], ...] = (
            (["xor", "-c", "-p", "-b", XOR_KEY], b"abc"),
            (["rsa", "-c", "-p", RSA_KEYS.public], b"too long for OAEP with n = 64 bytes"),
            (["aes", "-d", "-p", AES_KEY], AES_KEY.encode()),
            (["rsa", "-d", "-p", RSA_KEYS.private], b"8f84\n"),
        )
        for argv, stdin in cases:
            with self.subTest(argv=argv):
                self.assert_error(run(argv, stdin))


class TestSignature(FunctionalTestCase):
    def test_rsa(self) -> None:
        ciphered = run(["rsa", "-c", "-s", f"{RSA_KEYS.public}:{SIGNER_KEYS.private}"], b"The night is dark\n")
        self.assertEqual(len(ciphered.stdout.splitlines()), 2)
        result = run(["rsa", "-d", "-s", f"{RSA_KEYS.private}:{SIGNER_KEYS.public}"], ciphered.stdout)
        self.assert_success(result, b"The night is dark\n")

    def test_pgp_aes_with_padding(self) -> None:
        key: str = f"{AES_KEY}:{RSA_KEYS.public}:{SIGNER_KEYS.private}"
        ciphered = run(["pgp-aes", "-c", "-s", "-p", "pkcs1", key], b"All men must die\n")
        first_line, _, rest = ciphered.stdout.partition(b"\n")
        key = f"{first_line.decode()}:{RSA_KEYS.private}:{SIGNER_KEYS.public}"
        self.assert_success(run(["pgp-aes", "-d", "-s", "-p", "pkcs1", key], rest), b"All men must die\n")

    def test_forged_message_is_rejected_with_nothing_on_stdout(self) -> None:
        ciphered = run(["pgp-xor", "-c", "-s", f"{XOR_KEY}:{RSA_KEYS.public}:{SIGNER_KEYS.private}"], b"abc")
        first_line, cm, signature = ciphered.stdout.decode().splitlines()
        forged: bytes = f"{XOR_KEY}\n{signature}\n".encode()
        key: str = f"{first_line}:{RSA_KEYS.private}:{SIGNER_KEYS.public}"
        self.assert_error(run(["pgp-xor", "-d", "-s", key], forged))
        self.assert_success(run(["pgp-xor", "-d", "-s", key], f"{cm}\n{signature}\n".encode()), b"abc\n")

    def test_errors(self) -> None:
        cases: tuple[list[str], ...] = (
            ["xor", "-c", "-s", XOR_KEY],
            ["rsa", "-c", "-s", RSA_KEYS.public],
            ["rsa", "-c", "-s", f"{RSA_KEYS.public}:{SMALL_RSA_KEYS.private}"],
            ["pgp-aes", "-c", "-s", f"{AES_KEY}:{RSA_KEYS.public}"],
            ["rsa", "-d", "-s", f"{RSA_KEYS.private}:{SIGNER_KEYS.public}"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                self.assert_error(run(argv, b"8f84\n"))


class TestElGamal(FunctionalTestCase):
    def test_file_round_trip_is_identical(self) -> None:
        """Like the subject's X25519 example: cat file | -c | -d gives back the same file."""
        public, private = generated_keys(run(["elgamal", "-g", le_hex(SAFE_PRIME), le_hex(0xC0FFEE)]))
        files: tuple[bytes, ...] = (b"Winter is coming\n", b"no trailing newline", b"a\n\nb\n\n", b"", os.urandom(2000))
        for clear_file in files:
            ciphered = run(["elgamal", "-c", public], clear_file)
            with self.subTest(clear_file=clear_file[:10]):
                self.assertEqual(ciphered.code, 0, ciphered.stderr)
                self.assert_success(run(["elgamal", "-d", private], ciphered.stdout), clear_file)

    def test_random_keys(self) -> None:
        result = run(["elgamal", "-g", "-r", "128"])
        self.assertEqual((result.code, result.stderr), (0, b""))
        public, private = generated_keys(result)
        p: int = le_int(public.split("-")[2])
        self.assertTrue(p.bit_length() == 128 and is_probable_prime(p) and is_probable_prime((p - 1) // 2))
        ciphered = run(["elgamal", "-c", public], b"hello\n")
        self.assert_success(run(["elgamal", "-d", private], ciphered.stdout), b"hello\n")

    def test_errors(self) -> None:
        cases: tuple[tuple[list[str], bytes], ...] = (
            (["elgamal", "-g", "070001"], b""),
            (["elgamal", "-g", "070001", "00"], b""),
            (["elgamal", "-c", "01-02"], b"hello"),
            (["elgamal", "-d", "d204-02-070001"], b"not a pair\n"),
            (["elgamal", "-c", "-s", "d204-02-070001"], b"hello"),
        )
        for argv, stdin in cases:
            with self.subTest(argv=argv):
                self.assert_error(run(argv, stdin))


class TestOperationOption(FunctionalTestCase):
    def test_round_trips(self) -> None:
        message: bytes = os.urandom(1000)
        for flags, expected in ((["-m", "cbc"], zero_pad(message, 16)), (["-m", "cbc", "-p"], message),
                                (["-m", "ctr"], message), (["-m", "ecb"], zero_pad(message, 16))):
            ciphered = run(["aes", "-c", *flags, AES_KEY], message)
            with self.subTest(flags=flags):
                self.assertEqual(ciphered.code, 0, ciphered.stderr)
                self.assert_success(run(["aes", "-d", *flags, AES_KEY], ciphered.stdout), expected + b"\n")

    def test_pgp_aes(self) -> None:
        ciphered = run(["pgp-aes", "-c", "-m", "ctr", f"{AES_KEY}:{RSA_KEYS.public}"], b"All men must die")
        first_line, _, rest = ciphered.stdout.partition(b"\n")
        result = run(["pgp-aes", "-d", "-m", "ctr", f"{first_line.decode()}:{RSA_KEYS.private}"], rest)
        self.assert_success(result, b"All men must die\n")

    def test_errors(self) -> None:
        cases: tuple[tuple[list[str], bytes], ...] = (
            (["aes", "-c", "-b", "-m", "cbc", AES_KEY], b"0123456789abcdef"),
            (["aes", "-c", "-m", "ctr", "-p", AES_KEY], b"abc"),
            (["xor", "-c", "-m", "cbc", XOR_KEY], b"abc"),
            (["aes", "-d", "-m", "cbc", AES_KEY], b"00" * 20 + b"\n"),
            (["aes", "-d", "-m", "ctr", AES_KEY], b"0011\n"),
        )
        for argv, stdin in cases:
            with self.subTest(argv=argv):
                self.assert_error(run(argv, stdin))


class TestAuthenticationOption(FunctionalTestCase):
    def test_round_trip(self) -> None:
        for system, key, flags, expected in (("xor", XOR_KEY, [], b"Winter is coming\x00\x00"),
                                             ("aes", AES_KEY, ["-m", "ctr"], b"Winter is coming")):
            ciphered = run([system, "-c", "-a", *flags, key], b"Winter is coming")
            with self.subTest(system=system):
                self.assertEqual(ciphered.code, 0, ciphered.stderr)
                self.assert_success(run([system, "-d", "-a", *flags, key], ciphered.stdout), expected + b"\n")

    def test_modified_message_is_rejected_with_nothing_on_stdout(self) -> None:
        ciphered: str = run(["aes", "-c", "-a", "-m", "ctr", AES_KEY], b"pay 100 to Arya").stdout.decode().strip()
        forged: str = ciphered[:36] + ("0" if ciphered[36] != "0" else "1") + ciphered[37:]
        self.assert_error(run(["aes", "-d", "-a", "-m", "ctr", AES_KEY], forged.encode()))
        self.assert_error(run(["aes", "-d", "-a", "-m", "ctr", "00" * 16], ciphered.encode()))

    def test_pgp_xor(self) -> None:
        ciphered = run(["pgp-xor", "-c", "-a", f"{XOR_KEY}:{RSA_KEYS.public}"], b"abc")
        first_line, _, rest = ciphered.stdout.partition(b"\n")
        self.assert_success(run(["pgp-xor", "-d", "-a", f"{first_line.decode()}:{RSA_KEYS.private}"], rest), b"abc\n")


class TestRandomKeyOption(FunctionalTestCase):
    def test_round_trips(self) -> None:
        for system, message, expected in (("pgp-aes", b"All men must die!", zero_pad(b"All men must die!", 16)),
                                          ("pgp-xor", b"You know nothing", b"You know nothing")):
            ciphered = run([system, "-c", "-k", RSA_KEYS.public], message)
            first_line, _, rest = ciphered.stdout.partition(b"\n")
            with self.subTest(system=system):
                self.assertEqual(ciphered.code, 0, ciphered.stderr)
                self.assert_success(run([system, "-d", f"{first_line.decode()}:{RSA_KEYS.private}"], rest),
                                    expected + b"\n")

    def test_errors(self) -> None:
        for argv in (["pgp-aes", "-c", "-k", SMALL_RSA_KEYS.public], ["pgp-aes", "-d", "-k", RSA_KEYS.private],
                     ["pgp-aes", "-c", "-k", f"{AES_KEY}:{RSA_KEYS.public}"], ["aes", "-c", "-k", AES_KEY]):
            with self.subTest(argv=argv):
                self.assert_error(run(argv, b"hello"))


class TestDiffieHellman(FunctionalTestCase):
    def test_exchange_between_two_random_key_pairs(self) -> None:
        alice_public, alice_private = generated_keys(run(["dh", "-g", "-r"]))
        bob_public, bob_private = generated_keys(run(["dh", "-g", "-r"]))
        for clear_file in (b"Winter is coming\n", b"no trailing newline", b"", os.urandom(2000)):
            ciphered = run(["dh", "-c", f"{alice_private}:{bob_public}"], clear_file)
            with self.subTest(clear_file=clear_file[:10]):
                self.assertEqual(ciphered.code, 0, ciphered.stderr)
                self.assert_success(run(["dh", "-d", f"{bob_private}:{alice_public}"], ciphered.stdout), clear_file)
        ciphered = run(["dh", "-c", f"{alice_private}:{bob_public}"], b"hello")
        self.assert_error(run(["dh", "-d", f"{bob_private}:{bob_public}"], ciphered.stdout))

    def test_errors(self) -> None:
        public, private = generated_keys(run(["dh", "-g", le_hex(SAFE_PRIME), le_hex(0xC0FFEE)]))
        cases: tuple[list[str], ...] = (
            ["dh", "-g", "-r", "512"],
            ["dh", "-c", private],
            ["dh", "-c", f"{private}:{public}:{public}"],
            ["dh", "-c", f"{private}:d204-02-070001"],
            ["dh", "-c", "-s", f"{private}:{public}"],
        )
        for argv in cases:
            with self.subTest(argv=argv[:3]):
                self.assert_error(run(argv, b"hello"))


if __name__ == "__main__":
    unittest.main()
