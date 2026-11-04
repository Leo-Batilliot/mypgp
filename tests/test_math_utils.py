from __future__ import annotations

import math
import random
import unittest

from errors import MyPgpError
from math_utils import egcd, gcd, lcm, modexp, modinv


class TestGcdLcm(unittest.TestCase):
    def test_gcd_matches_stdlib(self) -> None:
        rng = random.Random(42)
        for _ in range(200):
            a, b = rng.randrange(0, 10**12), rng.randrange(0, 10**12)
            with self.subTest(a=a, b=b):
                self.assertEqual(gcd(a, b), math.gcd(a, b))

    def test_gcd_edge_cases(self) -> None:
        self.assertEqual(gcd(0, 5), 5)
        self.assertEqual(gcd(5, 0), 5)
        self.assertEqual(gcd(17, 13), 1)

    def test_lcm(self) -> None:
        self.assertEqual(lcm(4, 6), 12)
        self.assertEqual(lcm(60, 52), 780)
        self.assertEqual(lcm(7, 7), 7)


class TestEgcd(unittest.TestCase):
    def test_bezout_identity(self) -> None:
        rng = random.Random(1)
        for _ in range(200):
            a, b = rng.randrange(1, 10**12), rng.randrange(1, 10**12)
            g, x, y = egcd(a, b)
            with self.subTest(a=a, b=b):
                self.assertEqual(g, math.gcd(a, b))
                self.assertEqual(a * x + b * y, g)


class TestModinv(unittest.TestCase):
    def test_matches_builtin_pow(self) -> None:
        for a, m in ((3, 11), (17, 3120), (65537, 2**64 + 13), (257, 23730)):
            with self.subTest(a=a, m=m):
                inv: int = modinv(a, m)
                self.assertEqual(inv, pow(a, -1, m))
                self.assertTrue(0 <= inv < m)

    def test_no_inverse_raises(self) -> None:
        with self.assertRaises(MyPgpError):
            modinv(6, 9)


class TestModexp(unittest.TestCase):
    def test_matches_builtin_pow(self) -> None:
        rng = random.Random(7)
        for _ in range(200):
            base = rng.randrange(0, 2**256)
            exp = rng.randrange(0, 2**64)
            mod = rng.randrange(1, 2**256)
            with self.subTest(base=base, exp=exp, mod=mod):
                self.assertEqual(modexp(base, exp, mod), pow(base, exp, mod))

    def test_zero_exponent(self) -> None:
        self.assertEqual(modexp(123, 0, 7), 1)

    def test_modulus_one(self) -> None:
        self.assertEqual(modexp(5, 3, 1), 0)
        self.assertEqual(modexp(5, 0, 1), 0)

    def test_negative_exponent_raises(self) -> None:
        with self.assertRaises(MyPgpError):
            modexp(2, -1, 7)

    def test_non_positive_modulus_raises(self) -> None:
        for mod in (0, -7):
            with self.subTest(mod=mod), self.assertRaises(MyPgpError):
                modexp(2, 3, mod)


if __name__ == "__main__":
    unittest.main()
