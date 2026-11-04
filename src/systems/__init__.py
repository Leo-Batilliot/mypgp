from __future__ import annotations

from systems.aes import Aes
from systems.base import CryptoSystem
from systems.dh import DiffieHellman
from systems.elgamal import ElGamal
from systems.pgp import PgpAes, PgpXor
from systems.rsa import Rsa
from systems.xor import Xor

SYSTEMS: dict[str, type[CryptoSystem]] = {
    system.name: system for system in (Xor, Aes, Rsa, PgpXor, PgpAes, ElGamal, DiffieHellman)
}
