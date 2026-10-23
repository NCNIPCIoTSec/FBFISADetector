"""Discover or install the native Ghidra application without starting a JVM."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


SOURCE_ROOT = Path(__file__).resolve().parents[2]
USER_INSTALL = Path.home() / ".local" / "share" / "fbfisadetector" / "ghidra"


def is_installation(path: Path) -> bool:
    return (path / "support" / "launch.properties").is_file() and (
        path / "Ghidra" / "application.properties"
    ).is_file()


def find_ghidra(install_dir=None) -> Path:
    explicit = install_dir or os.environ.get("GHIDRA_INSTALL_DIR")
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if is_installation(path):
            return path
        raise FileNotFoundError(f"Not a Ghidra distribution: {path}")
    for parent in (SOURCE_ROOT / "requirements" / "ghidra" / "build" / "dist", USER_INSTALL):
        if is_installation(parent):
            return parent
        for path in sorted(parent.glob("ghidra_*"), reverse=True):
            if is_installation(path):
                return path.resolve()
    raise FileNotFoundError(
        "Ghidra not found. Set GHIDRA_INSTALL_DIR to an extracted distribution, "
        "or run fbfisa-ghidra --archive /path/to/ghidra.zip. "
        "The Ghidra source directory itself is not an installation."
    )


def install_archive(archive, destination) -> Path:
    destination = Path(destination).expanduser().resolve()
    with zipfile.ZipFile(archive) as bundle:
        # Validate before extracting anything, including the distribution layout.
        members = bundle.infolist()
        roots = {Path(item.filename).parts[0] for item in members if item.filename}
        if len(roots) != 1:
            raise ValueError("Expected a Ghidra distribution ZIP with one root directory")
        root = roots.pop()
        names = {item.filename for item in members}
        for name in ("support/launch.properties", "Ghidra/application.properties"):
            if f"{root}/{name}" not in names:
                raise ValueError(f"Not a Ghidra distribution ZIP: missing {name}")
        for item in members:
            target = (destination / item.filename).resolve()
            if not target.is_relative_to(destination) or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"Unsafe ZIP member: {item.filename}")
        target_root = destination / root
        if target_root.exists():
            raise FileExistsError(f"Destination already exists: {target_root}")
        for item in members:
            target = Path(bundle.extract(item, destination))
            mode = (item.external_attr >> 16) & 0o777
            if mode:
                target.chmod(mode)
    return find_ghidra(target_root)


def build_source(source, destination=None) -> Path:
    source = Path(source).expanduser().resolve()
    if not (source / "gradle" / "support" / "fetchDependencies.gradle").is_file():
        raise FileNotFoundError(f"Ghidra source submodule is not initialized: {source}")
    gradle = shutil.which("gradle")
    if not gradle:
        raise FileNotFoundError("Install Gradle and a supported JDK to build Ghidra")
    subprocess.run([gradle, "-I", "gradle/support/fetchDependencies.gradle"], cwd=source, check=True)
    subprocess.run([gradle, "buildGhidra"], cwd=source, check=True)
    dist = source / "build" / "dist"
    archives = sorted(dist.glob("ghidra_*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not archives:
        raise FileNotFoundError(f"No Ghidra distribution was built in {dist}")
    destination = Path(destination).expanduser().resolve() if destination else dist
    with zipfile.ZipFile(archives[0]) as bundle:
        root = Path(bundle.namelist()[0]).parts[0]
    if is_installation(destination / root):
        return (destination / root).resolve()
    return install_archive(archives[0], destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--archive", type=Path, help="install a local Ghidra distribution ZIP")
    actions.add_argument("--build-source", type=Path, help="build a Ghidra source checkout with Gradle")
    parser.add_argument("--destination", type=Path, help="ZIP extraction directory (default: user data directory for archives; build/dist for source builds)")
    args = parser.parse_args(argv)
    try:
        if args.archive:
            path = install_archive(args.archive, args.destination or USER_INSTALL)
        elif args.build_source:
            path = build_source(args.build_source, args.destination)
        else:
            path = find_ghidra()
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.CalledProcessError) as exc:
        print(f"Ghidra: {exc}", file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
