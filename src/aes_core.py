from __future__ import annotations

from errors import MyPgpError

AES_POLYNOMIAL: int = 0x11B
RCON: tuple[int, ...] = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def xtime(a: int) -> int:
    res: int = a << 1
    if res & 0x100:
        res ^= AES_POLYNOMIAL
    return res & 0xFF


def gmul(a: int, b: int) -> int:
    res: int = 0
    while b > 0:
        if b & 1:
            res ^= a
        a = xtime(a)
        b >>= 1
    return res


def gf_inverse(a: int) -> int:
    result: int = 1
    exp: int = 254
    while exp > 0:
        if exp & 1:
            result = gmul(result, a)
        a = gmul(a, a)
        exp >>= 1
    return result


def rotl8(a: int, shift: int) -> int:
    return ((a << shift) | (a >> (8 - shift))) & 0xff


def affine_transform(b: int) -> int:
    return b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63


def build_sboxes() -> tuple[tuple[int, ...], tuple[int, ...]]:
    sbox: list[int] = [affine_transform(gf_inverse(x)) for x in range(256)]
    inv_sbox: list[int] = [0] * 256
    for x, y in enumerate(sbox):
        inv_sbox[y] = x
    return tuple(sbox), tuple(inv_sbox)


SBOX, INV_SBOX = build_sboxes()


# MUL[c][x] == gmul(c, x) for the coefficients of MixColumns and InvMixColumns:
# computed once instead of 16 gmul loops per column and per round
def build_mul_tables(coefficients: tuple[int, ...]) -> dict[int, tuple[int, ...]]:
    return {c: tuple(gmul(c, x) for x in range(256)) for c in coefficients}


MUL: dict[int, tuple[int, ...]] = build_mul_tables((2, 3, 9, 11, 13, 14))

# The state is stored column by column: byte (row r, column c) is at index 4 * c + r.
# ShiftRows moves row r left by r columns, so new (r, c) = old (r, c + r):
# the 16 source indices are computed once instead of at every round.
SHIFT_ROWS: tuple[int, ...] = tuple(4 * ((c + r) % 4) + r for c in range(4) for r in range(4))
INV_SHIFT_ROWS: tuple[int, ...] = tuple(4 * ((c - r) % 4) + r for c in range(4) for r in range(4))


class AesCore:
    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise MyPgpError(f"invalid AES key: {len(key)} bytes (expected 16, 24 or 32)")
        self.nk: int = len(key) // 4
        self.nr: int = self.nk + 6
        self.round_keys: list[list[int]] = self.expand_key(key)

    @staticmethod
    def rot_word(word: list[int]) -> list[int]:
        return word[1:] + word[:1]

    @staticmethod
    def sub_word(word: list[int]) -> list[int]:
        return [SBOX[byte] for byte in word]

    def expand_key(self, key: bytes) -> list[list[int]]:
        words: list[list[int]] = [list(key[4 * i:4 * i + 4]) for i in range(self.nk)]
        for i in range(self.nk, 4 * (self.nr + 1)):
            temp: list[int] = words[i - 1]
            if i % self.nk == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp = [temp[0] ^ RCON[i // self.nk - 1]] + temp[1:]
            elif self.nk > 6 and i % self.nk == 4:
                temp = self.sub_word(temp)
            words.append([a ^ b for a, b in zip(words[i - self.nk], temp)])
        return [sum(words[4 * r:4 * r + 4], []) for r in range(self.nr + 1)]

    @staticmethod
    def sub_bytes(state: list[int]) -> list[int]:
        return [SBOX[byte] for byte in state]

    @staticmethod
    def inv_sub_bytes(state: list[int]) -> list[int]:
        return [INV_SBOX[byte] for byte in state]

    @staticmethod
    def shift_rows(state: list[int]) -> list[int]:
        return [state[i] for i in SHIFT_ROWS]

    @staticmethod
    def inv_shift_rows(state: list[int]) -> list[int]:
        return [state[i] for i in INV_SHIFT_ROWS]

    # [2 3 1 1], 
    # [1 2 3 1],
    # [1 1 2 3], 
    # [3 1 1 2]
    @staticmethod
    def mix_columns(state: list[int]) -> list[int]:
        m2, m3 = MUL[2], MUL[3]
        res: list[int] = []
        for c in range(4):
            a0, a1, a2, a3 = state[4 * c:4 * c + 4]
            res += [
                m2[a0] ^ m3[a1] ^ a2 ^ a3,
                a0 ^ m2[a1] ^ m3[a2] ^ a3,
                a0 ^ a1 ^ m2[a2] ^ m3[a3],
                m3[a0] ^ a1 ^ a2 ^ m2[a3],
            ]
        return res

    # [14 11 13 9],
    # [9 14 11 13],
    # [13 9 14 11], 
    # [11 13 9 14]
    @staticmethod
    def inv_mix_columns(state: list[int]) -> list[int]:
        m9, m11, m13, m14 = MUL[9], MUL[11], MUL[13], MUL[14]
        res: list[int] = []
        for c in range(4):
            a0, a1, a2, a3 = state[4 * c:4 * c + 4]
            res += [
                m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3],
                m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3],
                m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3],
            ]
        return res

    @staticmethod
    def add_round_key(state: list[int], round_key: list[int]) -> list[int]:
        return [byte ^ key for byte, key in zip(state, round_key)]


    def encrypt_block(self, block: bytes) -> bytes:
        self.check_block(block)
        state: list[int] = self.add_round_key(list(block), self.round_keys[0])
        for rnd in range(1, self.nr):
            state = self.mix_columns(self.shift_rows(self.sub_bytes(state)))
            state = self.add_round_key(state, self.round_keys[rnd])
        state = self.shift_rows(self.sub_bytes(state))
        state = self.add_round_key(state, self.round_keys[self.nr])
        return bytes(state)


    def decrypt_block(self, block: bytes) -> bytes:
        self.check_block(block)
        state: list[int] = self.add_round_key(list(block), self.round_keys[self.nr])
        for rnd in range(self.nr - 1, 0, -1):
            state = self.inv_sub_bytes(self.inv_shift_rows(state))
            state = self.inv_mix_columns(self.add_round_key(state, self.round_keys[rnd]))
        state = self.inv_sub_bytes(self.inv_shift_rows(state))
        state = self.add_round_key(state, self.round_keys[0])
        return bytes(state)


    @staticmethod
    def check_block(block: bytes) -> None:
        if len(block) != 16:
            raise MyPgpError(f"AES block must be 16 bytes, got {len(block)}")
