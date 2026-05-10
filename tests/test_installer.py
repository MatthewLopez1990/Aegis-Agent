from __future__ import annotations

import os
import stat
import subprocess
import unittest
from pathlib import Path


class InstallerTests(unittest.TestCase):
    def test_installer_script_is_posix_shell_and_user_local(self) -> None:
        root = Path(__file__).resolve().parents[1]
        installer = root / "install.sh"

        self.assertTrue(installer.exists())
        self.assertTrue(os.access(installer, os.X_OK))

        text = installer.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh"))
        self.assertIn("python3 python", text)
        self.assertIn("~/.aegis-agent", text)
        self.assertIn("~/.local/bin", text)
        self.assertIn("source-copy", text)
        self.assertNotIn("sudo ", text)
        self.assertNotIn("npm ", text)
        self.assertNotIn("pnpm ", text)
        self.assertNotIn("yarn ", text)

        subprocess.run(["sh", "-n", str(installer)], check=True)


if __name__ == "__main__":
    unittest.main()
