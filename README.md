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

### The program does not work lol

```console
python example.py        
```

## Goals

The goal is to extract disassembled functions from PE executables. We'll want a pure function that takes a file as input and returns disassembled functions, along with their locations in the binary, e.g.,

```python

from dataclasses import dataclass


@dataclass(frozen=True)
class Function:
    """
    Crucial information from each function.

    # TODO: include any information that may be useful.
    """
    instructions: list[str]
    lower_offset: int
    upper_offset: int


def extract_functions_from_binary(file: Path) -> list[Function]:
    """
    Extract disassembled functions and their locations from a PE binary.

    Args:
        file: file to extract from

    Returns:
        information about each function in the file
    """
    ...
```

Eventually, we'll want to parallelize this, so a pure function is easiest to work with.

There are many aspects of this problem that we will need to consider, e.g., architectures, instruction sets, obfuscations, etc. For now, start with the simplest variation of this problem and we'll refine the specifications as we go. Depending on the difficulty of the task, we may be able to write a similar function that extracts basic blocks and write dedicated functions for different architectures, e.g., x86, x64, ARM, etc., or file types, e.g., Android APK, Linux ELF, Mac Mach-O etc.

## Resources

### Tools

- [redare2-r2pipe](https://github.com/radareorg/radare2-r2pipe/tree/master)
- [Capstone](https://www.capstone-engine.org/lang_python.html)
- [LIEF](https://lief-project.github.io/doc/latest/index.html)
- [pefile](https://github.com/erocarrera/pefile)

### Reference

- [r2book](https://book.rada.re/disassembling/intro.html)
- [r2disassembleCheatSheet](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/)

### Papers

#### Surveys

Survey papers are probably the best way to introduce yourself to a new research topic.

- [From Hack to Elaborate Technique—A Survey on Binary Rewriting](https://dl.acm.org/doi/pdf/10.1145/3316415) (2019)
- [Adversarial EXEmples: A Survey and Experimental Evaluation of Practical Attacks on Machine Learning for Windows Malware Detection](https://dl.acm.org/doi/pdf/10.1145/3473039) (2021)
- [A Survey of Binary Code Similarity](https://dl.acm.org/doi/pdf/10.1145/3446371) (2021)
- [Arms Race in Adversarial Malware Detection: A Survey](https://dl.acm.org/doi/pdf/10.1145/3484491) (2021)
- [Deep Learning for Android Malware Defenses: A Systematic Literature Review](https://dl.acm.org/doi/pdf/10.1145/3544968) (2022)
- [A Survey on Ransomware: Evolution, Taxonomy, and Defense Solutions](https://dl.acm.org/doi/pdf/10.1145/3514229) (2022)
- [File Packing from the Malware Perspective: Techniques, Analysis Approaches, and Directions for Enhancements](https://dl.acm.org/doi/pdf/10.1145/3530810) (2022)
- [Deep Learning for Zero-day Malware Detection and Classification: A Survey](https://dl.acm.org/doi/pdf/10.1145/3605775) (2023)
- [A Survey of Malware Analysis Using Community Detection Algorithms](https://dl.acm.org/doi/10.1145/3610223) (2023)

#### Papers

These are some top-tier paper closely related to this project.

Malware classification from raw bytes
- [Malware Detection by Eating a Whole EXE](https://arxiv.org/pdf/1710.09435.pdf) (2018)
- [Classifying Sequences of Extreme Length with Constant Memory Applied to Malware Detection](https://ojs.aaai.org/index.php/AAAI/article/download/17131/16938) (2021) 
- [Recasting Self-Attention with Holographic Reduced Representations](https://proceedings.mlr.press/v202/alam23a/alam23a.pdf) (2023)

Malware classification from (not) raw bytes
- [SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection](https://arxiv.org/pdf/2012.07634.pdf) (2020)
- [DANdroid: A Multi-View Discriminative Adversarial Network for Obfuscated Android Malware Detection](https://dl.acm.org/doi/pdf/10.1145/3374664.3375746?casa_token=N9x3mDIeS4wAAAAA:7KwB1epI52fGCjZ6zp3LpP4DrirFjfNc89d-8Nx31t8HmR2ci2c7uIKx3AaylNTk76FHUUsgwErU) (2020)
- [Maat: Automatically Analyzing VirusTotal for Accurate Labeling and Effective Malware Detection](https://dl.acm.org/doi/pdf/10.1145/3465361) (2021)

Binary analysis with deep learning
- [Neural Network-based Graph Embedding for Cross-Platform Binary Code Similarity Detection](https://dl.acm.org/doi/pdf/10.1145/3133956.3134018) (2017)
- [PalmTree: Learning an Assembly Language Model for Instruction Embedding](https://dl.acm.org/doi/pdf/10.1145/3460120.3484587) (2021)
- [DeepDi: Learning a Relational Graph Convolutional Network Model on Instructions for Fast and Accurate Disassembly](https://www.usenix.org/system/files/sec22-yu-sheng.pdf) (2022)

Sequence-to-sequence modeling
- [Style Transfer Through Back-Translation](https://aclanthology.org/P18-1080.pdf) (2018)
- [Unsupervised Translation of Programming Languages](https://proceedings.neurips.cc/paper/2020/file/ed23fbf18c2cd35f8c7f8de44f85c08d-Paper.pdf) (2020)
- [Leveraging Automated Unit Tests for Unsupervised Code Translation](https://arxiv.org/pdf/2110.06773.pdf) (2022)

Adversarial malware generation
- [Intriguing Properties of Adversarial ML Attacks in the Problem Space](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9152781&casa_token=9LV3kGWFehQAAAAA:MoGsKNpPN8sG0lmxYK4nwA_EAYouowv5332hLCppLAFSf3qu-EFamD9zj2ueDzaLpmQTLltmpA) (2020)
- [Malware Makeover: Breaking ML-based Static Analysis by Modifying Executable Bytes](https://dl.acm.org/doi/pdf/10.1145/3433210.3453086) (2021)
- [Structural Attack against Graph Based Android Malware Detection](https://dl.acm.org/doi/pdf/10.1145/3460120.3485387?casa_token=GBAL7553auMAAAAA:oxYEOx9IoWQN3713JF9JAw2hMdQ1O0o2hYS-h0FiZnlv8ijCLt5Db1hcOAPPMNIBDC97Q8ZoYZI7) (2021)

Adversarial malware defense
- [Adversarial Deep Ensemble: Evasion Attacks and Defenses for Malware Detection](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9121297&casa_token=rdqw8IRh3EQAAAAA:mfpGxMuH6ps2w4WhTQ5N3UkPbONqC9xVL_wr15-W2BuSa-FIklsDGWaHzR5VFBPB-vRJt8xUvg) (2020)
- [A Framework for Enhancing Deep Neural Networks Against Adversarial Malware](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9321695) (2021)
- [Adversarial Training for Raw-Binary Malware Classifiers](https://www.usenix.org/system/files/usenixsecurity23-lucas.pdf) (2023)
- [On The Empirical Effectiveness of Unrealistic Adversarial Hardening Against Realistic Adversarial Attacks](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10179316&casa_token=7qHQHdV92d8AAAAA:xSU5YoNNTJlv5CLJnFqgkEnYCQszE2X3kI36OzwRbsBcuBGc0kJvLRZVCDhZHvEga7Ml0XcgSw) (2023)
