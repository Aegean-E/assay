"""Launcher contract checks; execution is covered by the manual smoke run and CI."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class LauncherTests(unittest.TestCase):
    def test_windows_launcher_checks_python_and_defaults_to_demo(self):
        text = (ROOT / "run.cmd").read_text(encoding="utf-8")
        self.assertIn("sys.version_info >= (3, 10)", text)
        self.assertIn("-m assay demo", text)
        self.assertIn('"%~1"==""', text)

    def test_posix_launcher_checks_candidates_and_defaults_to_demo(self):
        text = (ROOT / "run.sh").read_text(encoding="utf-8")
        self.assertIn("python3 python", text)
        self.assertIn("sys.version_info >= (3, 10)", text)
        self.assertIn("set -- demo", text)

    def test_macos_launcher_delegates(self):
        text = (ROOT / "run.command").read_text(encoding="utf-8")
        self.assertIn("run.sh", text)
        self.assertIn('cd "$(dirname "$0")"', text)


if __name__ == "__main__":
    unittest.main()
