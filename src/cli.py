from __future__ import annotations

from errors import MyPgpError
from systems import SYSTEMS

MODES: tuple[str, ...] = ("-c", "-d", "-g")
GENERATING_SYSTEMS: tuple[str, ...] = ("rsa", "elgamal", "dh")
SIGNING_SYSTEMS: tuple[str, ...] = ("rsa", "pgp-xor", "pgp-aes")
PADDED_SYSTEMS: tuple[str, ...] = ("xor", "aes", "rsa", "pgp-xor", "pgp-aes")
RSA_PADDING_SYSTEMS: tuple[str, ...] = ("rsa", "pgp-xor", "pgp-aes")
# -p alone: OAEP for RSA (PKCS#7 for the symmetric systems, which have no choice)
PADDINGS: tuple[str, ...] = ("oaep", "pkcs1")
DEFAULT_PADDING: str = "oaep"
OPERATION_SYSTEMS: tuple[str, ...] = ("aes", "pgp-aes")
# -m: how the stream mode chains the blocks, ECB (each block on its own) by default
OPERATIONS: tuple[str, ...] = ("ecb", "cbc", "ctr")
AUTHENTICATED_SYSTEMS: tuple[str, ...] = ("xor", "aes", "pgp-xor", "pgp-aes")
RANDOM_KEY_SYSTEMS: tuple[str, ...] = ("pgp-xor", "pgp-aes")


class Args:
    def __init__(self, argv: list[str]) -> None:
        self.system: str | None = None
        self.mode: str | None = None
        self.block: bool = False
        self.signed: bool = False
        self.padding: str | None = None
        self.key: str | None = None
        # -g P Q (rsa) / -g P X (elgamal), or -g -r [BITS] for random keys
        self.p: str | None = None
        self.q: str | None = None
        self.random: bool = False
        self.bits: int | None = None
        # -m ecb|cbc|ctr, -a (HMAC tag), -k (random PGP symmetric key)
        self.operation: str = "ecb"
        self.authenticated: bool = False
        self.random_key: bool = False
        self.parse(argv)

    # ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]: the mode always comes right
    # after the crypto system, then the options may appear anywhere among the rest.
    def parse(self, argv: list[str]) -> None:
        if not argv:
            raise MyPgpError("no arguments, use ./my_pgp -h")
        if argv[0] not in SYSTEMS:
            raise MyPgpError(f"unknown crypto system '{argv[0]}'")
        self.system = argv[0]
        if len(argv) < 2:
            raise MyPgpError("missing mode (-c, -d or -g)")
        if argv[1] not in MODES:
            raise MyPgpError(f"unknown mode '{argv[1]}' (expected -c, -d or -g)")
        self.mode = argv[1]

        rest: list[str] = argv[2:]
        if self.mode == "-g":
            rest = self.parse_generation(rest)
        self.block, rest = self.take_flag(rest, "-b")
        self.signed, rest = self.take_flag(rest, "-s")
        self.check_signature()
        rest = self.parse_padding(rest)
        rest = self.parse_operation(rest)
        self.authenticated, rest = self.take_flag(rest, "-a")
        self.random_key, rest = self.take_flag(rest, "-k")
        self.check_options()
        self.parse_key(rest)

    def parse_generation(self, rest: list[str]) -> list[str]:
        if self.system not in GENERATING_SYSTEMS:
            raise MyPgpError("-g is only available with rsa, elgamal and dh")
        if rest and rest[0] == "-r":
            self.random = True
            if len(rest) >= 2 and rest[1].isdigit():
                self.bits = int(rest[1])
                return rest[2:]
            return rest[1:]
        if len(rest) >= 2 and "-b" not in rest[:2] and "-r" not in rest[:2]:
            self.p, self.q = rest[0], rest[1]
            return rest[2:]
        return rest

    # -s is ignored with rsa -g, as it always was
    def check_signature(self) -> None:
        if not self.signed:
            return
        if self.mode == "-g":
            if self.system != "rsa":
                raise MyPgpError("-s can't be used with -g")
            self.signed = False
        elif self.system not in SIGNING_SYSTEMS:
            raise MyPgpError(f"-s is not available with {self.system}")

    # -p [oaep|pkcs1]
    def parse_padding(self, rest: list[str]) -> list[str]:
        if "-p" not in rest:
            return rest
        if self.mode == "-g":
            raise MyPgpError("-p can't be used with -g")
        if self.system not in PADDED_SYSTEMS:
            raise MyPgpError(f"-p is not available with {self.system}")
        index: int = rest.index("-p")
        end: int = index + 1
        self.padding = DEFAULT_PADDING
        if end < len(rest) and rest[end] in PADDINGS:
            if self.system not in RSA_PADDING_SYSTEMS:
                raise MyPgpError(f"{self.system} only has PKCS#7 padding: use -p alone")
            self.padding = rest[end]
            end += 1
        return rest[:index] + rest[end:]

    # -m ecb|cbc|ctr
    def parse_operation(self, rest: list[str]) -> list[str]:
        if "-m" not in rest:
            return rest
        if self.system not in OPERATION_SYSTEMS:
            raise MyPgpError(f"-m is not available with {self.system}")
        index: int = rest.index("-m")
        if index + 1 >= len(rest) or rest[index + 1] not in OPERATIONS:
            raise MyPgpError(f"-m needs a mode of operation: {', '.join(OPERATIONS)}")
        self.operation = rest[index + 1]
        return rest[:index] + rest[index + 2:]

    # -m, -a and -k work on the stream mode of the symmetric systems
    def check_options(self) -> None:
        if self.authenticated and self.system not in AUTHENTICATED_SYSTEMS:
            raise MyPgpError(f"-a is not available with {self.system}")
        if self.random_key and self.system not in RANDOM_KEY_SYSTEMS:
            raise MyPgpError(f"-k is not available with {self.system}")
        if self.random_key and self.mode != "-c":
            raise MyPgpError("-k only works with -c: deciphering needs the ciphered symmetric key")
        if self.block and (self.operation != "ecb" or self.authenticated):
            raise MyPgpError("-m and -a can't be used with -b: block mode ciphers a single block")
        # aes: -p would only be PKCS#7 (pgp-aes: -p also pads the RSA key, that stays)
        if self.operation == "ctr" and self.padding is not None and self.system not in RSA_PADDING_SYSTEMS:
            raise MyPgpError("-p can't be used with -m ctr: CTR pads nothing")

    # Options that only some systems take (refused above for the others): only the ones
    # given are passed on, so a system that has none of them is built as it always was
    def options(self) -> dict[str, str | bool]:
        options: dict[str, str | bool] = {}
        if self.operation != "ecb":
            options["operation"] = self.operation
        if self.authenticated:
            options["authenticated"] = True
        if self.random_key:
            options["random_key"] = True
        return options

    # Only the first occurrence is an option: a second one is a positional argument
    @staticmethod
    def take_flag(rest: list[str], flag: str) -> tuple[bool, list[str]]:
        if flag not in rest:
            return False, rest
        index: int = rest.index(flag)
        return True, rest[:index] + rest[index + 1:]

    def parse_key(self, rest: list[str]) -> None:
        if self.mode == "-g":
            if rest:
                raise MyPgpError("a key can't be used with -g")
            if not self.random and (self.p is None or self.q is None):
                raise MyPgpError("-g needs two numbers (-g P Q) or -r [BITS]")
            return
        if not rest or not rest[0]:
            raise MyPgpError("missing key")
        if len(rest) > 1:
            raise MyPgpError(f"too many arguments: '{' '.join(rest[1:])}'")
        self.key = rest[0]
