"""Runtime paths and architecture configuration."""

from __future__ import annotations

import os
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = PACKAGE_DIR / "config"

# Source checkouts contain resources next to the package. Installed wheels do
# not, so use the caller's working directory as the default data root there.
_SOURCE_ROOT = PACKAGE_DIR.parent.parent
_DATA_ROOT = _SOURCE_ROOT if (_SOURCE_ROOT / "resources").is_dir() else Path.cwd()

CONFIG_DIR = str(CONFIG_PATH)
SAMPLES_DIR = os.environ.get(
    "FBFISA_SAMPLES_DIR", str(_DATA_ROOT / "resources" / "samples")
)
OUTPUT_DIR = os.environ.get("FBFISA_OUTPUT_DIR", str(_DATA_ROOT / "output"))


def _architecture_files() -> dict[str, str]:
    arch_dir = CONFIG_PATH / "arch"
    if not arch_dir.is_dir():
        return {}
    return {path.stem: str(path) for path in sorted(arch_dir.glob("*.json"))}


ARCH_INFO = _architecture_files()


def ensure_output_dir() -> Path:
    """Create and return the configured output directory when needed."""

    output = Path(OUTPUT_DIR)
    output.mkdir(parents=True, exist_ok=True)
    return output
