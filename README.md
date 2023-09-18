# AssemblyFunctionExtraction

## Setup

Install dependencies, e.g., using a conda environment named {ENV} & pip
```console
conda create --name {ENV} python=3.10
conda activate {ENV}
pip install r2pipe lief pefile capstone tokenizers
```

## Usage

### Disassembly pipeline

```console
python pipeline.py --file_or_dir="file.exe"
```

```console
python pipeline.py --file_or_dir="directory"         
```

```console
python pipeline.py --help         
```

### Virtual-physical address map

```console
python address.py --build --merge
```

```console
python address.py --help
```

### Program does not work lol

```console
python example.py        
```

## Goals

The goal is to extract disassembled functions from PE executables. We'll want a pure function that takes a file as input and returns disassembled functions, along with their locations in the binary, e.g.,

```python
def extract_functions_from_binary(file: Path) -> list[tuple[str, int, int]]:
    """
    Extract disassembled functions and their locations from a PE binary.

    Args:
        file: file to extract from

    Returns:
        for each function, its disassembly, the offset in the binary at
            which the function begins, and the offset at which it ends.
    """
    ...
```

There are many aspects of this problem that we will need to consider, e.g., architectures, instruction sets, obfuscations, etc. For now, start with the simplest variation of this problem and we'll refine the specifications as we go. Depending on the difficulty of the task, we may be able to write a similar function that extracts basic blocks and expand the file types we can handle, e.g., Android APK, Linux ELF, etc.

## Tools

- [redare2-r2pipe](https://github.com/radareorg/radare2-r2pipe/tree/master)
- [Capstone](https://www.capstone-engine.org/lang_python.html)
- [LIEF](https://lief-project.github.io/doc/latest/index.html)
- [pefile](https://github.com/erocarrera/pefile)

## Resources


- [r2book](https://book.rada.re/disassembling/intro.html)
- [r2disassembleCheatSheet](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/)
