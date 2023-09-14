# AssemblyFunctionExtraction

## Setup

Install dependencies, e.g., using a conda environment named {ENV} & pip
```console
conda create --name {ENV} python=3.10
conda activate {ENV}
pip install r2pipe lief pefile capstone
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

## Tools

- [redare2-r2pipe](https://github.com/radareorg/radare2-r2pipe/tree/master)
- [Capstone](https://www.capstone-engine.org/lang_python.html)
- [LIEF](https://lief-project.github.io/doc/latest/index.html)
- [pefile](https://github.com/erocarrera/pefile)


## Resources

- [r2book](https://book.rada.re/disassembling/intro.html)
- [r2disassembleCheatSheet](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/)
