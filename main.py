"""
Extract functions from binaries.
"""

from __future__ import annotations
from argparse import ArgumentParser
from collections import UserDict
from collections.abc import Collection, Iterable
from copy import deepcopy
import csv
from dataclasses import dataclass
from collections import defaultdict
from itertools import chain
import os
import json
from multiprocessing import Pool
from pathlib import Path
import pefile as pe
from pprint import pprint
from random import shuffle
import re
import shutil
import signal
import subprocess
import sys
import time
import typing as tp
import warnings

import r2pipe


UPX = None  # "path/to/upx/if/you/have/it"
WARNS = [
    ("Functions with same addresses detected", False),
    ("Function addresses improperly parsed", False),
]


class PDRParser:
    def __init__(self, f: Path):
        self.idx = 0
        r2 = r2pipe.open(f.as_posix())
        r2.cmd("aaaa")
        self.output = r2.cmd("pdr @@f").split("\n")

    def __iter__(self):
        return self

    def __len__(self):
        return len(self.output)

    def __next__(self):
        if self.idx == len(self):
            raise StopIteration
        func = []
        add = False
        look_for_start = False
        start = None
        end = None
        while self.idx < len(self):
            line = self.output[self.idx]
            self.idx += 1
            if not line:
                continue
            if look_for_start and start is None:
                try:
                    start = int(self._extract_address(line), 16)
                    look_for_start = False
                except ValueError:
                    start = None
            if self._indicates_end(line) and start:
                try:
                    end = int(self._extract_address(line), 16)
                except ValueError:
                    end = None
                if not self._indicates_start(line):
                    func.append(line)
                else:
                    self.idx -= 1
                return start, end, func
            if self._indicates_start(line):
                if add:
                    try:
                        end = int(self._extract_address(line), 16)
                    except ValueError:
                        end = None
                    self.idx -= 1
                    return start, end, func
                add = True
                look_for_start = True
                start = None
            if add:
                func.append(line)
        if func:
            return start, end, func
        raise StopIteration

    @staticmethod
    def _extract_address(line: str) -> str:
        return line[2:13]

    @staticmethod
    def _indicates_end(line: str) -> bool:
        if line[0] in ("└", "┌", "├"):
            return True
        return False

    @staticmethod
    def _indicates_start(line: str) -> bool:
        if line[0] in ("┌", "├"):
            return True
        return False


def disassemble(f: Path, dest_path: Path) -> list[Path]:
    outpath = dest_path / f.stem
    if outpath.exists():
        return []
    outpath.mkdir()
    parser = PDRParser(f)
    for i, (start, end, func) in enumerate(parser):
        f_out = outpath / f"{start}_{end}.asm"
        if f_out.exists():
            warnings.warn(f"{WARNS[0][0]} @{i=} {f=}")
            if WARNS[0][1]:
                continue
        if start is None or end is None:
            warnings.warn(f"{WARNS[1][0]} @{i=} {f=}")
            if WARNS[1][1]:
                continue
        with open(f_out, "w") as handle:
            handle.write("\n".join(func))
    return list(outpath.iterdir())


def filter_(
    f: Path,
    dest_path: Path,
    max_len: int = int(1e6),
    _16_bit: bool = False,
    _32_bit: bool = True,
    _64_bit: bool = False
) -> tuple[Path, int]:
    def ret(keep: bool):
        f_out = dest_path / f.name
        if keep:
            f.rename(f_out)
        else:
            f.unlink()
        return f_out

    if f.stat().st_size == 0:
        return ret(False), 1
    if f.stat().st_size > max_len:
        return ret(False), 2

    try:
        header = pe.PE(f.as_posix()).FILE_HEADER
    except pe.PEFormatError:
        return ret(False), 3

    if header.IMAGE_FILE_16BIT_MACHINE and not _16_bit:
        return ret(False), 4
    if header.IMAGE_FILE_32BIT_MACHINE and not _32_bit:
        return ret(False), 5
    if not header.IMAGE_FILE_16BIT_MACHINE and not header.IMAGE_FILE_32BIT_MACHINE and not _64_bit:
        return ret(False), 6

    return ret(True), 0


def unpack(f: Path, dest_path: Path) -> Path:
    f_out = dest_path / f.name
    if UPX is None:
        return f_out
    command = [UPX, "-d", f"{f.as_posix()}", "-o", f"{f_out.as_posix()}"]
    result = subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    )
    if result.returncode == 1:
        f.rename(f_out)
    elif result.returncode == 2:
        f.rename(f_out)
    else:
        f.unlink()
    return f_out


def main(f: Path) -> None:
    wd = Path(".")
    f = unpack(f, wd)
    r = filter_(f)[1]
    if r != 0:
        sys.exit(r)
    f = disassemble(f, wd)


def cli() -> None:
    parser = ArgumentParser()
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    main(args.file)


if __name__ == "__main__":
    main()
