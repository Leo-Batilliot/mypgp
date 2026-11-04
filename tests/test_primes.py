from __future__ import annotations

import unittest

from errors import MyPgpError
from primes import SMALL_PRIMES, is_probable_prime, random_prime, random_safe_prime
from tests.helpers import is_probable_prime as oracle_is_prime


class TestMillerRabin(unittest.TestCase):
    def test_small_numbers_match_trial_division(self) -> None:
        for n in range(-5, 5000):
            expected: bool = n >= 2 and all(n % d for d in range(2, int(n ** 0.5) + 1))
            with self.subTest(n=n):
                self.assertEqual(is_probable_prime(n), expected)

    def test_carmichael_numbers_are_composite(self) -> None:
        # Fool Fermat's test for every coprime base, not Miller-Rabin
        for n in (561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185, 5394826801):
            with self.subTest(n=n):
                self.assertFalse(is_probable_prime(n))

    def test_known_large_primes(self) -> None:
        for n in (2**127 - 1, 2**521 - 1, 65537, 1000000007):
            with self.subTest(n=n):
                self.assertTrue(is_probable_prime(n))

    def test_product_of_two_large_primes(self) -> None:
        self.assertFalse(is_probable_prime((2**127 - 1) * (2**89 - 1)))

    def test_small_primes_table(self) -> None:
        self.assertEqual(SMALL_PRIMES[:6], (2, 3, 5, 7, 11, 13))
        self.assertEqual(SMALL_PRIMES[-1], 1999)


class TestRandomPrimes(unittest.TestCase):
    def test_random_prime_has_the_requested_size(self) -> None:
        for bits in (2, 3, 8, 16, 64, 256, 512):
            with self.subTest(bits=bits):
                p: int = random_prime(bits)
                self.assertEqual(p.bit_length(), bits)
                self.assertTrue(oracle_is_prime(p))

    def test_random_primes_differ(self) -> None:
        self.assertEqual(len({random_prime(128) for _ in range(5)}), 5)

    def test_random_safe_prime(self) -> None:
        for bits in (3, 17, 64, 256):
            with self.subTest(bits=bits):
                p: int = random_safe_prime(bits)
                self.assertEqual(p.bit_length(), bits)
                self.assertTrue(oracle_is_prime(p))
                self.assertTrue(oracle_is_prime((p - 1) // 2))

    def test_too_few_bits(self) -> None:
        with self.assertRaises(MyPgpError):
            random_prime(1)
        with self.assertRaises(MyPgpError):
            random_safe_prime(2)


if __name__ == "__main__":
    unittest.main()
