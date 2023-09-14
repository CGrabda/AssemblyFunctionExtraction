"""
Demonstrate that the program does not work.
"""

from collections import Counter, defaultdict
from pprint import pprint

from address import FunctionBoundaries
from cfg import BOUNDARIES, FILTERED


results = defaultdict(Counter)
mapper = FunctionBoundaries.load(BOUNDARIES)
for name, addr_map in mapper.items():
    file = FILTERED / name
    size = file.stat().st_size
    for virt_addr, (lower, upper) in addr_map.items():
        if lower < 0:
            results[name].update([1])
        if upper < 0:
            results[name].update([2])
        if upper <= lower:
            results[name].update([3])
        if lower > size:
            results[name].update([4])
        if upper > size:
            results[name].update([5])
        if not results[name]:
            results[name].update([0])

pprint(results)

