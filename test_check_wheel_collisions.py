#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

import tempfile
import unittest

from pathlib import Path

import check_wheel_collisions as cwc


class TestCheckWheelCollisions(unittest.TestCase):
    def test_no_collision_unique_basenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "a" / "foo-1.0-py3-none-any.whl").write_bytes(b"a")
            (root / "b" / "bar-1.0-py3-none-any.whl").write_bytes(b"b")
            self.assertEqual(cwc.collect_collision_errors(root), [])

    def test_collision_same_basename_different_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "linux-armv7").mkdir()
            (root / "linux-armv7legacy").mkdir()
            name = "pkg-1.0-cp39-cp39-linux_armv7l.whl"
            (root / "linux-armv7" / name).write_bytes(b"v1")
            (root / "linux-armv7legacy" / name).write_bytes(b"v2-different")
            errs = cwc.collect_collision_errors(root)
            self.assertEqual(len(errs), 1)
            self.assertIn(name, errs[0])

    def test_same_basename_identical_bytes_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x").mkdir()
            (root / "y").mkdir()
            name = "same-1.0-py3-none-any.whl"
            payload = b"identical"
            (root / "x" / name).write_bytes(payload)
            (root / "y" / name).write_bytes(payload)
            self.assertEqual(cwc.collect_collision_errors(root), [])

    def test_main_returns_one_on_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "linux-armv7").mkdir()
            (root / "linux-armv7legacy").mkdir()
            name = "dup-1.0-cp39-cp39-linux_armv7l.whl"
            (root / "linux-armv7" / name).write_bytes(b"1")
            (root / "linux-armv7legacy" / name).write_bytes(b"2")
            self.assertEqual(cwc.main(["_", str(root)]), 1)

    def test_collision_ci_artifact_directory_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wheels-repaired-linux-armv7").mkdir()
            (root / "wheels-repaired-linux-armv7legacy").mkdir()
            name = "pkg-1.0-cp39-cp39-linux_armv7l.whl"
            (root / "wheels-repaired-linux-armv7" / name).write_bytes(b"v1")
            (root / "wheels-repaired-linux-armv7legacy" / name).write_bytes(b"v2-different")
            errs = cwc.collect_collision_errors(root)
            self.assertEqual(len(errs), 1)
            self.assertIn(name, errs[0])

    def test_pure_universal_wheel_digest_mismatch_ignored(self) -> None:
        """py3-none-any (etc.) may differ between ARMv7 Docker lineages; not a fatal clash."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "linux-armv7").mkdir()
            (root / "linux-armv7legacy").mkdir()
            name = "charset_normalizer-3.4.7-py3-none-any.whl"
            (root / "linux-armv7" / name).write_bytes(b"zip-a")
            (root / "linux-armv7legacy" / name).write_bytes(b"zip-b")
            self.assertEqual(cwc.collect_collision_errors(root), [])

    def test_benign_same_basename_other_lineages_ignored(self) -> None:
        """macOS x86 vs ARM repair trees (or any non-ARMv7 pair) may differ; not a merge failure."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wheels-repaired-macos-arm64").mkdir()
            (root / "wheels-repaired-macos-x86_64").mkdir()
            name = "crypt-1.0-cp38-abi3-macosx_10_9_universal2.whl"
            (root / "wheels-repaired-macos-arm64" / name).write_bytes(b"a")
            (root / "wheels-repaired-macos-x86_64" / name).write_bytes(b"b")
            self.assertEqual(cwc.collect_collision_errors(root), [])


if __name__ == "__main__":
    unittest.main()
