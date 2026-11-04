from __future__ import annotations

import secrets
from typing import Callable

from padding import xor_bytes

# Ciphers or deciphers one block (AES: 16 bytes)
BlockFunction = Callable[[bytes], bytes]


# IV (CBC) or first counter block (CTR): random, not secret, never twice the same
def new_iv(size: int) -> bytes:
    return secrets.token_bytes(size)


# CBC (NIST SP 800-38A): each block is XORed with the previous ciphered block before
# being ciphered, the first one with the IV. Equal blocks no longer give equal ciphered blocks.
# C[i] = E(P[i] ^ C[i - 1]), C[0] = IV. `data` is made of whole blocks.
def cbc_encrypt(encrypt: BlockFunction, iv: bytes, data: bytes) -> bytes:
    size: int = len(iv)
    previous: bytes = iv
    blocks: list[bytes] = []
    for i in range(0, len(data), size):
        previous = encrypt(xor_bytes(data[i:i + size], previous))
        blocks.append(previous)
    return b"".join(blocks)


# P[i] = D(C[i]) ^ C[i - 1]
def cbc_decrypt(decrypt: BlockFunction, iv: bytes, data: bytes) -> bytes:
    size: int = len(iv)
    chained: bytes = iv + data
    return b"".join(
        xor_bytes(decrypt(chained[i + size:i + 2 * size]), chained[i:i + size])
        for i in range(0, len(data), size)
    )


# CTR (NIST SP 800-38A): the block cipher turns the counters into a keystream, XORed with
# the data like a XOR key as long as the message. Ciphering and deciphering are the same
# operation, only `encrypt` is used, and nothing is padded: the keystream is cut to the data.
# The counter is a big-endian number, incremented modulo 2^(8 * block size).
def ctr_crypt(encrypt: BlockFunction, counter: bytes, data: bytes) -> bytes:
    size: int = len(counter)
    start: int = int.from_bytes(counter, "big")
    keystream: bytes = b"".join(
        encrypt(((start + i) % (1 << (8 * size))).to_bytes(size, "big"))
        for i in range((len(data) + size - 1) // size)
    )
    return xor_bytes(data, keystream)
