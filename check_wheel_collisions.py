#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""Detect ARMv7 vs ARMv7 Legacy wheel basename clashes under a merged tree.

Used after downloading per-arch ``wheels-repaired-*`` artifacts into separate
subdirectories (``merge-multiple: false``). The same ``*.whl`` basename can also
appear under other pairs of trees (for example ``py3-none-any`` rebuilt on every
runner, or ``macosx_*_universal2`` repaired on both macOS jobs); those may
legitimately differ by hash and are **not** errors here. Only collisions between
**Linux ARMv7** and **Linux ARMv7 Legacy** lineages are fatal — see README
(ARMv7 vs ARMv7 Legacy). Pure universal wheels (platform tag ``any`` only) are
skipped even under ARMv7 vs Legacy, because ZIP digests can differ without a
native binary lineage conflict.
"""

from __future__ import annotations

import hashlib
import sys

from collections import defaultdict
from pathlib import Path

from packaging.utils import InvalidWheelFilename
from packaging.utils import parse_wheel_filename

# Top-level directory names under the staging root (matches upload-artifact names
# in wheels-repair.yml). Tests use shorter stand-ins.
_ARMV7_STAGING_DIRS = frozenset(
    {
        "wheels-repaired-linux-armv7",
        "linux-armv7",
    }
)
_ARMV7_LEGACY_STAGING_DIRS = frozenset(
    {
        "wheels-repaired-linux-armv7legacy",
        "linux-armv7legacy",
    }
)


def _armv7_lineage(path: Path, root: Path) -> str | None:
    """Return ``armv7``, ``armv7legacy``, or None based on the first path segment under root."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    if len(rel.parts) < 2:
        return None
    top = rel.parts[0]
    if top in _ARMV7_STAGING_DIRS:
        return "armv7"
    if top in _ARMV7_LEGACY_STAGING_DIRS:
        return "armv7legacy"
    return None


def _is_pure_universal_wheel(filename: str) -> bool:
    """True if every build tag in the wheel is ``*-none-any`` / ``*-py2.py3-none-any`` style.

    Such wheels are not Linux-ARM-specific binaries; ARMv7 vs Legacy repair often
    produces different ZIP bytes (metadata, tool versions) without a glibc/ELF
    lineage conflict that this check is meant to catch.
    """
    try:
        _name, _version, _build, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return False
    return bool(tags) and all(tag.platform == "any" for tag in tags)


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def collect_collision_errors(root: Path) -> list[str]:
    """Return human-readable error lines; empty if OK.

    Only reports when the same basename appears under **both** ARMv7 and ARMv7
    Legacy staging trees with **more than one** distinct file digest across
    those two trees, and the wheel is **not** a pure universal (``platform`` tag
    ``any`` only) artifact.
    """
    wheels: list[Path] = []
    for p in sorted(root.rglob("*.whl")):
        if p.is_file():
            wheels.append(p)

    by_name: defaultdict[str, list[Path]] = defaultdict(list)
    for p in wheels:
        by_name[p.name].append(p)

    errors: list[str] = []
    for name, paths in sorted(by_name.items()):
        armv7 = [p for p in paths if _armv7_lineage(p, root) == "armv7"]
        legacy = [p for p in paths if _armv7_lineage(p, root) == "armv7legacy"]
        if not armv7 or not legacy:
            continue
        if _is_pure_universal_wheel(name):
            continue
        lineage_paths = armv7 + legacy
        by_digest: defaultdict[str, list[Path]] = defaultdict(list)
        for p in lineage_paths:
            by_digest[_sha256_file(p)].append(p)
        if len(by_digest) == 1:
            continue
        lines = [f"ARMv7 vs ARMv7 Legacy wheel basename clash (different contents): {name}"]
        for digest, ps in sorted(by_digest.items()):
            for p in ps:
                lines.append(f"  - {p}  sha256={digest}")
        errors.append("\n".join(lines))
    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    if not root.is_dir():
        print(f"Error: not a directory: {root}", file=sys.stderr)
        return 2

    errors = collect_collision_errors(root)
    if errors:
        print("Wheel basename collision check failed:\n", file=sys.stderr)
        for block in errors:
            print(block, file=sys.stderr)
            print(file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
