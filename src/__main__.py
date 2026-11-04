from __future__ import annotations

import sys

from cli import Args
from dispatch import Dispatcher
from errors import MyPgpError

USAGE: str = """USAGE
      ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

DESCRIPTION
Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. The MESSAGE is read from the standard input.

   CRYPTO_SYSTEM
      "xor"            computation using XOR algorithm
      "aes"            computation using AES algorithm
      "rsa"            computation using RSA algorithm
      "pgp-xor"        computation using both RSA and XOR algorithm
      "pgp-aes"        computation using both RSA and AES algorithm

   MODE
      -c               MESSAGE is clear and we want to cipher it
      -d               MESSAGE is ciphered and we want to decipher it
      -g P Q           RSA only: don't read a MESSAGE, but instead generate a public and private key
      pair from the prime number P and Q

   OPTIONS
      -b               for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric
      key must be the same size

   key                 Key used to cipher/decipher MESSAGE (incompatible with -g MODE)"""


def print_usage() -> None:
    print(USAGE)


def main() -> int:
    argv: list[str] = sys.argv[1:]
    if argv == ["-h"]:
        print_usage()
        return 0
    try:
        args: Args = Args(argv)
        Dispatcher(args).run()
    except MyPgpError as e:
        print(f"my_pgp: {e}", file=sys.stderr)
        return 84
    except Exception as e:
        print(f"my_pgp: unexpected error: {e}", file=sys.stderr)
        return 84
    return 0


if __name__ == "__main__":
    sys.exit(main())
