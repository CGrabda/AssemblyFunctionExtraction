"""
Global configurations.
"""

from pathlib import Path


# Directories where data is temporarily stored throughout the pipeline
OUTPUT = Path("./output")
SOURCE = OUTPUT / Path("./source")
UNPACKED = OUTPUT / Path("./unpacked")
FILTERED = OUTPUT / Path("./filtered")
DISASSEMBLED = OUTPUT / Path("./disassembled")
NORMALIZED = OUTPUT / Path("./normalized")
MERGED = OUTPUT / Path("./merged")
BOUNDARIES = OUTPUT / Path("boundaries.json")
_BOUNDARIES = OUTPUT / Path("boundaries")

# Add the path to the upx executable program, if installed
UPX = None

