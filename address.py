"""
Create a mapping from virtual to physical addresses for each binary in the corpus.
"""

from __future__ import annotations
from argparse import ArgumentParser
from collections import UserDict
from collections.abc import Collection
import json
import multiprocessing as mp
import os
from pathlib import Path
from pprint import pprint
import shutil
import sys
from typing import Any


import r2pipe

from cfg import BOUNDARIES, _BOUNDARIES, FILTERED


def build_function_address_map(f: Path) -> tuple[str, dict[str, tuple[int, int]]]:
    """
    Build a map between virtual addresses and physical bounds.

    Args:
     f: file to build the map for

    Returns:
     for convenicene, the file name
     a map between each functions virtual address (hexadecimal) and the (upper, lower)
      bounds of the function in the binary itself
    """
    r2 = r2pipe.open(f.as_posix())
    try:
        r2.cmd("aaaa")
        virt = redare_parse_function_addresses(r2.cmd("?p @@f"))
        phys = redare_parse_function_addresses(r2.cmd("?P @@f"))
        bounds = redare_parse_function_info(r2.cmd("afi @@f"))
    except BaseException:
        raise
    finally:
        r2.quit()

    if not all([virt, phys, bounds]):
        return f.name, {}
    if len(bounds) != len(virt) or len(bounds) != len(phys):
        return f.name, {}

    virt_to_bounds = {}
    for p, v in zip(phys, virt):
        l, u = None, None
        for l, u in bounds:
            if l == int(p, 16):
                virt_to_bounds[v] = (l, u)

    return (f.name, virt_to_bounds)


def redare_parse_function_info(out: str) -> list[tuple[int, int]]:
    """
    Return the upper and lower bounds for each function.

    Args:
     a string returned by r2's afi command

    Returns:
     a list of (upper, lower) bounds for each function
    """
    d = []
    for func_info in out.split("#")[1:]:
        offset = None
        size = None
        for line in func_info.split("\n"):
            if line[0:7] == "offset:":
                offset = int(line.split("offset:")[1].strip(), 16)
            if line[0:5] == "size:":
                size = int(line.split("size:")[1].strip())
        if offset is None or size is None:
            raise ValueError("Failed to parse function info.")
        d.append((offset, offset + size))
    return d


def redare_parse_function_addresses(out: str) -> list[str]:
    """
    Return a list of hexadecimal addresses extracted from out.

    Args:
     a string returned by r2's ?p or ?P commands

    Returns:
     a list of hexadecimal virtual addresses
    """
    lines = out.split("\n")
    locations = [s.find("0x") for s in lines]
    addresses = [s[i:] for s, i in zip(lines, locations) if i != -1]
    return addresses


class FunctionBoundaries(UserDict):
    """Maps the virtual address of a function to its physical bounds.
    
    Handles both Path and str indices seemlessly.
    Represents addresses as str hexadecimals or int decimals.

    Usage
    -----
        >>> fb = FunctionBoundaries.load("fb.json")
        >>> file = Path("f_1.exe.")
        >>> virtual = "0x00008d48"
        >>> fb[file][virtual]
        (1000, 1024)
    """

    def __getitem__(self, k: str | Path) -> dict[str, tuple[int, int]]:
        if isinstance(k, Path):
            k = k.name
        return super().__getitem__(k)

    def __setitem__(self, k: str | Path, v: dict[str, tuple[int, int]]) -> None:
        if isinstance(k, Path):
            k = k.name
        super().__setitem__(k, v)

    @classmethod
    def load(cls, file: Path, suffix: str = None) -> FunctionBoundaries:
        with open(file, "r") as handle:
            b = cls(json.load(handle))
        if isinstance(suffix, str):
            b.data = {Path(f).with_suffix(suffix).name : a for f, a in b.data.items()}
        return b

    @classmethod
    def build(cls, files: Collection[Path], n_workers: int = 1) -> FunctionBoundaries:
        with mp.Pool(n_workers) as pool:
            function_address_map = pool.map(build_function_address_map, files)
        function_address_map = {f: m for f, m in dict(function_address_map).items() if m}
        print(f"Succeeded on {len(function_address_map)} / {len(files)} files.")
        return cls(function_address_map)

    def as_hex(self) -> FunctionBoundaries:
        if self._current_mode() == "hex":
            return self

        for f in self.data:
            for a in self.data[f]:
                l = hex(self.data[f][a][0])
                u = hex(self.data[f][a][1])
                self.data[f][a] = (l, u)

        return self

    def as_dec(self) -> FunctionBoundaries:
        if self._current_mode() == "dec":
            return self

        for f in self.data:
            for a in self.data[f]:
                l = int(self.data[f][a][0], 16)
                u = int(self.data[f][a][1], 16)
                self.data[f][a] = (l, u)

        return self

    def save(self, file: Path) -> FunctionBoundaries:
        with open(file, "w") as fp:
            json.dump(self.data, fp, indent=2)
        return self

    def _current_mode(self) -> str:
        f = next(iter(self.data.keys()))
        a = next(iter(self.data[f].keys()))
        l = self.data[f][a][0]
        if isinstance(l, str):
            return "hex"
        elif isinstance(l, int):
            return "dec"
        raise ValueError()


def main(
    build: bool,
    merge: bool,
    remove: bool,
    batch_size: int,
    n_workers: int,
    sample: int = None,
) -> None:

    sample = None if sample == -1 else sample

    if build:
        _BOUNDARIES.mkdir(exist_ok=True)
        files = sorted(list(FILTERED.iterdir()))[0:sample]
        for i in range(0, len(files), batch_size):
            if (_BOUNDARIES / f"boundaries_{i}.json").exists():
                continue
            mapper = FunctionBoundaries.build(files[i : i + batch_size], n_workers)
            mapper.save(_BOUNDARIES / f"boundaries_{i}.json")

    if merge:
        mapper = FunctionBoundaries()
        for f in _BOUNDARIES.glob("boundaries_*.json"):
            m = FunctionBoundaries.load(f)
            print(len(m))
            mapper.update(m)
        print(len(mapper))
        mapper.save(BOUNDARIES)
        shutil.rmtree(_BOUNDARIES)


def cli():
    parser = ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--merge", action="store_true")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--batch_size", type=int, default=800)
    parser.add_argument("--n_workers", type=int, default=8)
    parser.add_argument("--sample", type=int, default=-1)
    args = parser.parse_args()
    
    main(args.build, args.merge, args.remove, args.batch_size, args.n_workers, args.sample)

if __name__ == "__main__":
    cli()
