"""
Things got a little crazy, so lets not even try to recover whatever the hell this code does.
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
import sys
from typing import Any

import r2pipe


# TODO: unfortunately, the redare commands contained in the this function return completely
# incorrect information the majority of the time, e.g., as with 
# 0023fb1b6a5c2aa742f1af297a026d1455325db8392f67be682f910c1fac384e.exe
def build_function_address_map(f: Path) -> tuple[str, dict[str, tuple[int, int]]]:
    """
    Return a mapping from a function's virtual address to its size.
    Return None if something goes wrong.
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
    """Return the upper and lower bounds for each function."""
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
    """Return a list of hexadecimal addresses extracted from out."""
    lines = out.split("\n")
    locations = [s.find("0x") for s in lines]
    addresses = [s[i:] for s, i in zip(lines, locations) if i != -1]
    return addresses
