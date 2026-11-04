from __future__ import annotations

from errors import MyPgpError


# Surrounding whitespace is ignored, and so is whitespace between two bytes
# (bytes.fromhex). An empty value is the empty byte string.
def hex_to_bytes(text: str) -> bytes:
    try:
        return bytes.fromhex(text.strip())
    except ValueError:
        raise MyPgpError("invalid hexadecimal value")


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_int(text: str) -> int:
    return int.from_bytes(hex_to_bytes(text), "little")


def int_to_hex(value: int) -> str:
    return bytes_to_hex(int_to_bytes(value))


def reverse(data: bytes) -> bytes:
    return data[::-1]


def reverse_words(data: bytes, size: int = 4) -> bytes:
    if size <= 0 or len(data) % size != 0:
        raise MyPgpError(f"data length is not a multiple of {size} bytes")
    result: bytearray = bytearray(len(data))
    for i in range(size):
        result[i::size] = data[size - 1 - i::size]
    return bytes(result)


def read_hex(data: bytes) -> bytes:
    try:
        text: str = data.decode("ascii")
    except UnicodeDecodeError:
        raise MyPgpError("input is not hexadecimal")
    return hex_to_bytes(text)


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def int_to_bytes(value: int) -> bytes:
    if value < 0:
        raise MyPgpError("negative numbers can't be encoded")
    length: int = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "little")
