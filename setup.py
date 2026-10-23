"""Packaging configuration for FBFISADetector."""

from pathlib import Path

from setuptools import Command, find_packages, setup


ROOT = Path(__file__).resolve().parent


class InstallGhidra(Command):
    """Install Ghidra separately from Python wheel installation."""

    description = "install a Ghidra distribution ZIP or build the supplied submodule"
    user_options = [
        ("archive=", None, "path to a Ghidra distribution ZIP"),
        ("destination=", None, "directory to extract the distribution into"),
        ("build-source", None, "build requirements/ghidra using Gradle"),
    ]
    boolean_options = ["build-source"]

    def initialize_options(self):
        self.archive = None
        self.destination = None
        self.build_source = False

    def finalize_options(self):
        pass

    def run(self):
        # Loading by path keeps metadata generation independent of runtime deps.
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "fbfisa_ghidra", ROOT / "src" / "addrsolver" / "ghidra.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        args = []
        if self.archive:
            args += ["--archive", self.archive]
        if self.destination:
            args += ["--destination", self.destination]
        if self.build_source:
            args += ["--build-source", str(ROOT / "requirements" / "ghidra")]
        if module.main(args):
            raise RuntimeError("Ghidra installation failed; see the error above")


setup(
    name="fbfisadetector",
    version="0.2.0",
    description="Identify the instruction set architecture and endianness of raw firmware binaries",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="QingYang",
    author_email="yqingiot@163.com",
    url="https://github.com/NCNIPCIoTSec/FBFISADetector",
    license="MIT",
    python_requires=">=3.11",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    py_modules=["detectisa", "elf2bin"],
    include_package_data=True,
    package_data={
        "fbfisa.config": ["*.json", "arch/*.json"],
        "emulator.config": ["*.json"],
        "agents": ["auth.conf.example"],
    },
    exclude_package_data={"agents": ["auth.conf"]},
    install_requires=[
        "sympy>=1.13.3",
        "pyelftools>=0.32",
        "numpy>=2.3.1",
        "matplotlib>=3.10.3",
        "pyghidra==3.2.0",
        "openai==3.37.0",
    ],
    entry_points={
        "console_scripts": [
            "detectisa=fbfisa.cli:main",
            "elf2bin=elf2bin:main",
            "solve-base=addrsolver.solvers:main",
            "fbfisa-ghidra=addrsolver.ghidra:main",
        ]
    },
    cmdclass={"install_ghidra": InstallGhidra},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
)
