from __future__ import annotations

import sys

from cli import Args
from errors import MyPgpError
from systems import SYSTEMS
from systems.base import AsymmetricSystem, CryptoSystem


class Dispatcher:
    def __init__(self, args: Args) -> None:
        if args.system is None or args.mode is None:
            raise MyPgpError("invalid arguments")
        self.args: Args = args
        self.mode: str = args.mode
        self.system: CryptoSystem = SYSTEMS[args.system](
            args.key, args.block, args.padding, args.signed, **args.options()
        )

    def run(self) -> None:
        output: bytes = self.execute()
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()

    def execute(self) -> bytes:
        if self.mode == "-g":
            return self.generate()
        self.system.check_key(self.mode)
        data: bytes = self.read_input()
        if self.mode == "-c":
            return self.system.cipher(data)
        return self.system.decipher(data)

    def generate(self) -> bytes:
        if not isinstance(self.system, AsymmetricSystem):
            raise MyPgpError(f"-g is not available with {self.system.name}")
        if self.args.random:
            return self.system.generate_random(self.args.bits)
        if self.args.p is None or self.args.q is None:
            raise MyPgpError("-g needs two numbers: -g P Q")
        return self.system.generate(self.args.p, self.args.q)

    def read_input(self) -> bytes:
        try:
            data: bytes = sys.stdin.buffer.read()
        except OSError as e:
            raise MyPgpError(f"cannot read standard input: {e}")
        # A single trailing line feed (echo) is not part of the message
        if self.system.strips_newline and data.endswith(b"\n"):
            return data[:-1]
        return data
