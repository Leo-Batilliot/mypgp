from __future__ import annotations

from errors import MyPgpError


# Greatest common divisor of a and b (Euclid's algorithm).
# Used by RSA keygen to check that e is coprime with λ(n): gcd(e, λ) must be 1.
def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a


# Least common multiple of a and b: a * b // gcd(a, b).
# Used by RSA keygen to compute the Carmichael function λ(n) = lcm(p - 1, q - 1).
def lcm(a: int, b: int) -> int:
    return a * b // gcd(a, b)


# Extended Euclid's algorithm: returns (g, x, y) such that a * x + b * y = g = gcd(a, b).
# Used by modinv to find the modular inverse (the x coefficient).
def egcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r != 0:
        q: int = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y


# Modular inverse of a modulo m: the d such that (a * d) % m == 1.
# Used by RSA keygen to compute the private exponent d = e⁻¹ mod λ(n).
def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise MyPgpError(f"{a} has no inverse modulo {m}")
    return x % m


# Fast modular exponentiation (square-and-multiply): (base ** exp) % mod
# without ever computing base ** exp.
# Used by RSA to cipher (c = m^e mod n) and decipher (m = c^d mod n).
def modexp(base: int, exp: int, mod: int) -> int:
    if exp < 0:
        raise MyPgpError("negative exponent")
    if mod <= 0:
        raise MyPgpError("modulus must be positive")
    result: int = 1 % mod
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result
