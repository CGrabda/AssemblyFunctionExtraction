"""
Extract functions from binaries.

Output
------
| -- output
    | -- source
    | -- unpacked
    | -- filterd
    | -- disassembled
    | -- normalized
    | -- merged

"""

from __future__ import annotations
from argparse import ArgumentParser, MetavarTypeHelpFormatter
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
from tqdm import tqdm
from tokenizers import normalizers, Regex

from cfg import (
    UPX,
    OUTPUT,
    SOURCE,
    UNPACKED,
    FILTERED,
    DISASSEMBLED,
    NORMALIZED,
    MERGED,
)


WARNS = [
    ("Functions with same addresses detected", False),
    ("Function addresses improperly parsed", False),
]


NORMALIZER = normalizers.Sequence(
    [
        normalizers.Replace(Regex(rx), rp)
        for rx, rp in [
            (r"^┌.*\n", ""),
            (r"^├.*\n", ""),
            (r"└", "│"),
            (r"^\|.*(?:\n|$)", ""),
            (r";.*", ""),
            (r"│ ", ""),
            (r"\n{2,}", "\n"),
            (r"^.{31}", ""),
            ("\n\n", "\n"),
        ]
    ]
)


class PDRParser:
    """
    Iterate over a binary's functions using r2's pdr command.
    """
    def __init__(self, f: Path):
        self.idx = 0
        r2 = r2pipe.open(f.as_posix())
        r2.cmd("aaaa")
        self.output = r2.cmd("pdr @@f").split("\n")

    def __iter__(self) -> PDRParser:
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


def _process_text(text: str) -> str:
    """
    Final text processing step to simply output.
    """
    # Remove spaces at the beginning and end of a line
    text = re.sub(r"^ +| +$", "", text, flags=re.MULTILINE)
    # Replace more than one space with a single space
    text = re.sub(r" +", " ", text)
    # Replace more than one newline character with a single newline character
    text = re.sub(r"\n+", "\n", text)
    # Ensure ends with newline
    text = text.lstrip().rstrip() + "\n"

    return text


def merge(d: Path, dest_path: Path) -> Path:
    """
    Merges a directory containing a large number of short asm files into a single txt.
    
    Args:
     d: directory containing asm files to merge
     dest_path: directory to dump merged file in
    
    Returns:
     the new file
    """
    out_file = (dest_path / d.stem).with_suffix(".txt")
    data = []
    for f in d.glob("*.asm"):
        with open(f) as handle:
            s = handle.read()
        s = _process_text(s)
        data.append(f"{f.stem}\n{s}")
    with open(out_file, "w") as handle:
        handle.write(f"{'-'*42}\n".join(data))
    shutil.rmtree(d, ignore_errors=True)
    return out_file


def normalize(f: Path, dest_path: Path) -> Path:
    """
    A preliminary normalization stage to remove r2 residuals.
    
    Args:
     f: the file to process
     dest_path: directory to dump new file in
    
    Returns:
     the new file
    """
    d_out = dest_path / f.parent.name
    d_out.mkdir(exist_ok=True)
    f_out = d_out / f.name
    with open(f) as handle:
        out_str = NORMALIZER.normalize_str(handle.read())
    out_str = out_str.lstrip().rstrip() + "\n"
    with open(f_out, "w") as handle:
        handle.write(out_str)
    f.unlink()
    return f_out


def disassemble(f: Path, dest_path: Path) -> list[Path]:
    """
    Disassemble the functions of a binary into several individual asm files.

    Each asm file is named according to the start and end of the corresponding
     function's virtual addresses. All asm files are placed in a new directory
     named after the file to be disassembled.

    Args:
     f: the file to process
     dest_path: directory to dump disassembled functions

    Returns:
     files of disassembled functions
    """
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
    max_len: int = float("inf"),
    _16_bit: bool = False,
    _32_bit: bool = True,
    _64_bit: bool = False
) -> tuple[Path, int]:
    """
    Determine whether a binary should continue along the disassembly pipeline.

    Args:
     f: the file to process
     dest_path: directory to dump new file in
     max_length: filter binaries larger than this
     _16_bit: if True, include binaries compiled for 16-bit architectures
     _32_bit: if True, include binaries compiled for 32-bit architectures
     _64_bit: if True, include binaries compiled for 64-bit architectures
    
    Returns:
     the new file and a status code representing the reason the binary may not
      be selected to move forward in the pipeline
    """
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
    """
    Try to unpack binaries using upx.
    
    Args:
     f: the file to process
     dest_path: directory to dump new file in
    
    Returns:
     the new file
    """
    f_out = dest_path / f.name
    if UPX is None:
        warnings.warn("UPX not found. Skipped attempted unpacking.")
        return f
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


def run(file: Path) -> None:
    """
    Run the entire pipeline for a single file.

    Args:
     f: the file to run
    """
    file = unpack(file, UNPACKED)
    file, r = filter_(file, FILTERED)
    if r != 0:
        sys.exit(r)
    files = disassemble(file, DISASSEMBLED)
    for f in files:
        normalize(f, NORMALIZED)
    merge(NORMALIZED / file.stem, MERGED)


def main() -> None:
    parser = ArgumentParser(formatter_class=MetavarTypeHelpFormatter)
    parser.add_argument("--file_or_dir", type=Path, help="File or directory of files to analyze.")
    parser.add_argument("--sample", type=int, default=-1, help="Optional subset of files.")
    args = parser.parse_args()
    
    OUTPUT.mkdir(exist_ok=True)
    SOURCE.mkdir(exist_ok=True)
    UNPACKED.mkdir(exist_ok=True)
    FILTERED.mkdir(exist_ok=True)
    DISASSEMBLED.mkdir(exist_ok=True)
    MERGED.mkdir(exist_ok=True)
    NORMALIZED.mkdir(exist_ok=True)

    if args.file_or_dir.is_dir():
        files = list(args.file_or_dir.iterdir())
    else:
        files = [args.file_or_dir]

    for f in files:
        shutil.copy2(f, SOURCE)

    files = list(SOURCE.iterdir())
    for f in tqdm(files):
        run(f)


if __name__ == "__main__":
    main()
