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
from json import loads

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


#(r"^┌.*\n", ""),
#(r"^├.*\n", ""),
#(r"└", "│"),
#(r"^\|.*(?:\n|$)", ""),
#(r";.*", ""),
#(r"│ ", ""),
#(r"\n{2,}", "\n"),
#(r"^.{31}", ""),
#("\n\n", "\n"),



def disassemble(f: Path, disassembled) -> list[tuple[list, list, list, list, list]]:
    """
    Returns: list of tuples containing information associated with each function. 
        0 offsets to the beginning of each instruction in the function
        1 bytes of the instructions
        2 disassembly of the instructions
        3 length of each instruction
        4 arguments to the function
    """

    # Initialize radare2
    r2 = r2pipe.open(f.as_posix())

    # Analyze all basic blocks
    r2.cmd("aab")

    # Analyze all functions
    r2.cmd("aac")

    # Get radare2 output as text
    disassembly = r2.cmd("pdr @@f")
    r2.quit()


    # Group all functions using regex
    # 
    # Identifies 2 or more lines of repeated code (| or │ character at start of line with assembly)
    # followed or not followed by the end of a function (└ character at start of line with assembly)
    # and captures the entire group
    assemblyFunctions = re.findall("((?:(?:│|\|).+\n){2,}(?:└.+\n){1})", disassembly)
    parsedFunctions = []

    
    # Iterate over each function
    for func in assemblyFunctions:
        bytesList = []
        offsetList = []
        disassemblyList = []
        bytesLengthList = []
        argumentList = []

        # Splits the function into each instruction
        instructions = func.split("\n")


        
        # Loop over each instruction
        for i in range(len(instructions)):
            # Split the line into its parts
            tokens = instructions[i].split()

            # Filters out comments
            # R2 comments use a different | character to start the line or are an assembly comment ; 
            if len(tokens) > 0 and tokens[0] != "|" and tokens[1][0] != ";" and tokens[1][-1] != ":":
                # Add offset to offset list
                offsetList.append(tokens[1])
                
                # Add instruction raw bytes to the bytes list
                # figure out what . character means
                # ------Convert from string to hex representation int(tokens[2], 16)
                bytesList.append(tokens[2])

                # Add readable disassembly to disassembly list
                disassemblyList.append(tokens[3:])

                # Add the length of the instruction to the byte length list
                bytesLengthList.append(len(tokens[2]))
            elif instructions[i][:7] == "│ ; arg":
                # Split args into tokens
                argumentList.append(instructions[i].split(" "))

            # Adds functions details to parsed functions list as a tuple
            parsedFunctions.append((offsetList, bytesList, disassemblyList, bytesLengthList, argumentList))

    return parsedFunctions
        
    


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
