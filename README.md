# FBFISADetector

FBFISADetector (Filter-Based Firmware ISA Detector) identifies the instruction set architecture (ISA) and endianness of monolithic firmware and other raw binary images. It uses an explainable, non-machine-learning expert system built around byte-block filtering, instruction patterns, and relationships between instructions.

**Documentation:** English (this file) · [中文文档](README_ZH.md)

## Why this project exists

Knowing the ISA and byte order is an essential first step when analyzing firmware. Product labels and hardware documentation are often incomplete, unavailable, or damaged, while a wrong architecture assumption can make every later static or dynamic analysis fail. FBFISADetector reduces this initial manual work and supports large-scale firmware triage.

The detector currently supports ARM, MIPS, PowerPC, RISC-V 64, and TriCore. It focuses on monolithic firmware, where code and data are commonly mixed and an ELF header is unavailable, and can also process ELF-derived raw binaries.

## Installation

Python 3.11 or newer is required. The repository contains source submodules for Capstone, pypcode, and Unicorn. These copies provide the architecture coverage expected by this project, so install them before packages with the same names from PyPI. PyPI wheels may cover fewer target architectures on some platforms.

Clone the repository and initialize every submodule:

~~~bash
git clone --recursive https://github.com/NCNIPCIoTSec/FBFISADetector.git
cd FBFISADetector

# If the repository was already cloned:
git submodule update --init --recursive
~~~

Create a virtual environment and install dependencies:

~~~bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install "cmake>=3.18" build nanobind "setuptools-scm>=8"
python -m pip install --no-build-isolation -r requirements.txt
python -m pip install --no-deps .
~~~

A C/C++ compiler and Make (or the platform build tools) are required. The local path entries in requirements.txt build regular wheels from the supplied submodules:

| Component | Repository path | Version in this checkout |
| --- | --- | --- |
| Capstone | requirements/capstone/bindings/python | 6.0.0-alpha4 |
| pypcode | requirements/pypcode | 3.2.2.dev0 |
| Unicorn | requirements/unicorn/bindings/python | version derived from the pinned Git checkout |

Do not replace these entries with unpinned PyPI package names when architecture coverage matters. setup.py intentionally does not list these three packages in install_requires, because pip would otherwise be free to select a different distribution. Install requirements.txt first, then install this project with --no-deps as shown above. The package JSON configuration files are included in the installed distribution.

The core detector does not depend on angr. The previous requirements snapshot included angr 9.2.165, which requires Capstone 5.0.3 and therefore cannot be resolved together with this repository's Capstone 6.0.0-alpha4. angr and its related analysis packages are intentionally excluded from the core environment; install them in a separate environment only for legacy scripts that explicitly need them.

For development, use an editable project install:

~~~bash
python -m pip install --no-deps -e .
~~~

### Base-address dependencies and Ghidra installation

Both requirements.txt and setup.py include **pyghidra==3.2.0** and **openai==3.37.0**. Ghidra itself is a Java/native application and is installed separately; `pip install .` installs its Python bridge, not the Ghidra distribution. ISA identification and Unicorn emulation do not require Ghidra or an LLM service. The python-javabridge submodule is not required by PyGhidra.

Install a 64-bit JDK supported by your Ghidra distribution (JDK 21 for the supplied source checkout), and set `JAVA_HOME` if it is not already configured. Choose one Ghidra installation method:

~~~bash
# Build the supplied source submodule (requires Gradle 8.5+, network and native build tools):
python setup.py install_ghidra --build-source

# Or install a locally downloaded/built Ghidra distribution ZIP:
python setup.py install_ghidra --archive /path/to/ghidra_distribution.zip
# Installed command with the same ZIP installer:
fbfisa-ghidra --archive /path/to/ghidra_distribution.zip

# Or use an existing extracted distribution:
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1_DEV
export JAVA_HOME=/path/to/jdk-21
fbfisa-ghidra                 # print the detected installation directory
~~~

The installer extracts ZIPs into `~/.local/share/fbfisadetector/ghidra` by default; override with `--destination /path/to/directory`. Source builds are extracted under `requirements/ghidra/build/dist`. The solver searches `--ghidra-dir`, `GHIDRA_INSTALL_DIR`, the checkout's build/dist directory, then the default user installation directory. Point to a distribution containing `support/launch.properties` and `Ghidra/application.properties`, rather than the Ghidra source root. Python package installation never builds/downloads Ghidra implicitly.

### Capstone build troubleshooting

Use the two-step build-tool installation and `--no-build-isolation` command above. The supplied Capstone build invokes CMake without declaring it as an isolated build dependency; a Python-based CMake executable outside pip's isolated environment can fail with `ModuleNotFoundError: cmake`, followed by missing `libcapstone.so.6`. Regular local wheel installs also avoid Capstone's custom editable-build failure. The project itself can still be installed editable. Do not change the submodule to the PyPI Capstone wheel to work around this error.

## Command-line usage

### Detect one binary

After installation, the console entry point can be called from any directory:

~~~bash
detectisa -f /path/to/firmware.bin
detectisa -p -f /path/to/firmware.bin              # enable multiprocessing
detectisa -p -a ARM -f /path/to/firmware.bin       # test one architecture
~~~

The required -f/--file option points to the input image. Use detectisa --help to see all options. The -a/--arch option limits analysis to a selected architecture profile.

When working directly from a source checkout, use:

~~~bash
python src/detectisa.py -f /path/to/firmware.bin
~~~

### Convert ELF to a raw binary

Use elf2bin when an ELF file must be converted to the raw image expected by the detector:

~~~bash
elf2bin -f /path/to/file.elf -o /path/to/output_dir
elf2bin -f /path/to/file.elf -o /path/to/output_dir --print-path
~~~

The converter extracts file-backed `PT_LOAD` segments at their physical load addresses, fills gaps with `0xff`, and excludes BSS. It returns `<stem>_<base>.bin`; `--print-path` writes only that path to stdout for scripts. It rejects overlapping segments and images spanning more than 256 MiB.

### Solve a firmware base address

Configure the LLM classifier with environment variables, or copy `src/agents/auth.conf.example` to a private INI file and pass `--llm-config /path/to/auth.conf` (also supported through `FBFISA_LLM_CONFIG`):

~~~bash
export OPENAI_API_KEY=your_api_key
export OPENAI_MODEL=your_model_name
# Optional for a compatible endpoint; default is https://api.openai.com/v1:
export OPENAI_BASE_URL=https://your-endpoint.example/v1
# Optional: chat (default) or responses:
export OPENAI_API_STYLE=chat

solve-base -b /path/to/firmware.bin -v ARM:LE:32:Cortex -m '(0x365c, 0x368f)'
# Static analysis only, with no API key or API requests:
solve-base -b /path/to/firmware.bin -v ARM:LE:32:Cortex --no-llm
~~~

`-v` is a Ghidra language ID; `-m` supplies an optional inclusive **file-offset** disassembly range. Analysis runs after this manual disassembly so discovered functions contribute to inference. `-r` optionally overrides pointer byte width (2, 4 or 8). `--workspace` or `FBFISA_GHIDRA_WORKSPACE` selects the project directory (default: a `fbfisa-ghidra` directory in the system temporary directory). Source checkout usage is `PYTHONPATH=src python -m addrsolver.solvers ...`.

Results report a candidate base address and an entry offset; when both are known, the entry address is their sum. Cortex-M reset vectors take precedence over the call-graph entry heuristic. Cortex-M vector evidence requires an aligned base and in-image handler targets; handler prologues also contribute when Ghidra has not created functions for them. Equally scored candidates prefer page alignment; unresolved ties and insufficient evidence produce `unknown`. Candidate ranking is heuristic, and `--no-llm` skips the model-based classification of pointers and shifted constants, so fewer binaries yield a result. Call-graph entry estimates may differ from the original ELF entry; validate inferred addresses before using them for firmware analysis.

### Sample scripts

These Bash scripts resolve paths relative to the checkout and can run from another directory. They use `.venv/bin/python` when present, otherwise `python3`; set `PYTHON=/path/to/python` to select another environment. They honor `FBFISA_SAMPLES_DIR` and `FBFISA_OUTPUT_DIR`.

| Script | Purpose | Example |
| --- | --- | --- |
| `test_ba.sh` | Base-address inference for ARM, TriCore, PowerPC and MIPS samples | `bash test_ba.sh --no-llm` |
| `test_emu.sh` | Simple Unicorn execution of the ARM gateway sample | `bash test_emu.sh` |
| `test_samples.sh` | ISA identification of the ARM drone ELF and extracted raw image | `bash test_samples.sh` |

Run `FBFISA_TEST_ARCH=arm bash test_ba.sh --no-llm` to test just ARM. Without `--no-llm`, configure the classifier first. Solver options such as `--ghidra-dir` and `--workspace` are forwarded by `test_ba.sh`. All selected sample files must be present, including the separately supplied TriCore sample. The Unicorn example maps basic RAM/MMIO and stops at its instruction limit or an emulation error; it does not model the board's peripherals.

With static analysis, the supplied ARM gateway sample yields base `0x08000000` and reset-entry offset `0x365c`; the MIPS sample yields candidate base `0x00400000`. The supplied TriCore and PowerPC samples currently return `unknown` without the model classifier. Run regression tests with `PYTHONPATH=src python -m unittest discover -s tests -v`.

### Batch example

src/main.py contains a batch-oriented example:

~~~bash
python src/main.py
~~~

### Sample and output directories

For a source checkout, samples default to resources/samples and results default to output. Override those locations when using a separate data directory:

~~~bash
export FBFISA_SAMPLES_DIR=/path/to/resources/samples
export FBFISA_OUTPUT_DIR=/path/to/output
~~~

## Python API

The core analyzer can be called from Python. Installed configuration data is exposed through fbfisa.settings.CONFIG_DIR:

~~~python
import os

from fbfisa.analysis.instruction_analysis import BinaryAnalyzer
from fbfisa.settings import ARCH_INFO, CONFIG_DIR

BinaryAnalyzer.updateSupportedArch(ARCH_INFO)
BinaryAnalyzer.loadBrachCalculationExpressions(
    os.path.join(CONFIG_DIR, "call_branch.json")
)
analyzer = BinaryAnalyzer("/path/to/firmware.bin")
result = analyzer.analyzing()
print(result)
~~~

Call BinaryAnalyzer.openMultiProcessing() before analyzing() when parallel analysis is useful.

## Research background

### Related work

- [Binwalk](https://github.com/refirmlabs/binwalk) is a widely used binary and firmware identification tool.
- **CCFC DFRWS 2015 — [Automatic classification of object code using machine learning](https://www.sciencedirect.com/science/article/pii/S1742287615000523)** introduced ISA identification with byte-value histograms. It represents opcode density and special two-byte values such as 0x0001 and 0xfffe to infer byte order. In embedded firmware, lookup tables and operands can dominate byte frequencies and obscure the opcode signal.
- **CCFC DIMVA 2018 — [ELISA: ELiciting ISA of Raw Binaries for Fine-Grained Code and Data Separation](https://link.springer.com/chapter/10.1007/978-3-319-93411-2_16)** combines ISA identification with code/data separation and patterns for known function prologues and epilogues from angr's archinfo project. Pattern matches can still land in operands or tables, and the method remains largely frequency-based rather than modeling instruction semantics.
- **ACM CODASPY 2020 — [ISAdetect: Usable Automated Detection of CPU Architecture and Endianness for Executable Binary Files and Object Code](https://dl.acm.org/doi/10.1145/3374664.3375742)** addresses the lack of public datasets and provides APIs that make earlier machine-learning approaches easier to reproduce. Its associated [dataset](https://etsin.fairdata.fi/dataset/80fa69af-addb-4f9a-b45c-c16011bae366) is mainly ELF-based, where section and symbol information makes code-region labeling easier.
- **IEEE TIFS 2023 — [A Natural Language Processing Approach for Instruction Set Architecture Identification](https://ieeexplore.ieee.org/document/10159173)** uses byte n-grams, TF-IDF, and character-level base encodings. TF-IDF reduces the influence of common padding such as 0xff and 0x00, while two-byte features help with endianness. Base-32 and Base-85 can reorder instruction information and introduce noise when encoded groups do not align with instruction boundaries.
- **Computer Science Journal 2024 — [A firmware ISA identification method based on function-call instruction features](https://doi.org/10.11896/jsjkx.230500087)** proposes EDFIR, which combines opcode and operand information around candidate function calls. It distinguishes PC-relative and base-address-relative targets and scores architectures using validated call candidates and their ranges. The approach still relies on manually selected thresholds and statistical features, and it does not fully model register addressing.

### Challenges addressed by this project

Earlier approaches generally quantify bytes and send the resulting vector to a classifier. They often miss relationships between opcodes and operands and provide limited semantic information about instruction sequences or memory-mapped I/O. Firmware makes this harder because code, padding, lookup tables, and metadata can be interleaved and the correct byte offset for feature extraction is not known in advance.

FBFISADetector uses a non-machine-learning expert system based on pattern extraction and relationships between instructions. This keeps filtering decisions inspectable, avoids dependence on a large multi-architecture training corpus, and makes adding an architecture a configuration and analysis task rather than a complete model retraining cycle.

### Technical approach

The detector searches for architecture-specific instruction pairs and related byte patterns. Examples include stack pairs such as push {lr, rx, ry}/pop {pc, rx, ry} and conditional pairs such as cmp/bxx. It uses these patterns to split candidate byte blocks, applies instruction and intermediate-representation checks, and scores the remaining evidence for each architecture and endianness.

Architecture patterns and branch/call expressions are kept in JSON configuration files so the expert rules are easy to inspect and extend. Recovering complete function boundaries would improve semantic checks, but that is difficult for static analysis of raw firmware. Existing IR checks remove many invalid non-code blocks, while some data-region blocks can still pass and require further validation.

For the complete method description, see the TrustCom 2025 paper: [FBFISADetector: A Method based on Filter Mechanism to detect the Instruction Set Architecture of Monolithic Firmware](https://ieeexplore.ieee.org/document/11354569).

## Evaluation

The evaluation uses real ARM Cortex-M firmware from the [Monolithic Firmware Collection](https://github.com/ucsb-seclab/monolithic-firmware-collection.git) and the [dataset summarized by ISAdetect](https://etsin.fairdata.fi/dataset/80fa69af-addb-4f9a-b45c-c16011bae366/data). The latter is primarily ELF-based, so section names and symbols make code-region localization convenient. A provider download can use wget --content-disposition with a valid token.

Tested profiles cover mainstream embedded systems (ARM and RISC-V), automotive electronics (TriCore), network equipment (MIPS), and industrial equipment (PowerPC). x86 is not currently included: it is less representative of resource-constrained monolithic firmware, and variable-length CISC instructions make byte-block boundaries and operand false positives more difficult to handle.

![Precision results](./resources/data/images/precision.png)

The detailed experiment setup and additional results are available in the paper. The original evaluation reported two null results for ELF-ARM, five null results and one TriCore result for ELF-RISC-V-64, and one ARM result for ELF-TriCore.

## Limitations and future work

- **Expert-rule effort:** Creating instruction-pair rules requires reading ISA manuals and checking samples. This is the main reason the current release covers five architecture profiles. Future work could mine instruction relationships to generate configuration entries automatically.
- **IR validation:** Filtering of non-code blocks can be improved while preserving valid code blocks. More complete semantic consistency checks are needed.
- **Small or low-semantic inputs:** When a binary contains little recognizable instruction context, instruction-pair filtering can remove every candidate block and reduce accuracy. Combining semantic evidence with a controlled frequency signal may help.
- **Rule balance:** Weak instruction pairs produce too few blocks; too many pairs make the method approach frequency analysis, reduce performance, and can increase false positives for another architecture such as TriCore. A better balance or a hybrid strategy remains open.

## License

This project is distributed under the MIT License. See the repository for the license text and third-party component notices.
