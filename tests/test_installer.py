from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
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
        self.assertIn("MatthewLopez1990/Aegis-Agent", text)
        self.assertIn("DEFAULT_ARCHIVE_URL", text)
        self.assertIn("curl -fsSL https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/install.sh | sh", text)
        self.assertIn("source-copy", text)
        self.assertNotIn("YOUR_ORG", text)
        self.assertNotIn("sudo ", text)
        self.assertNotIn("npm ", text)
        self.assertNotIn("pnpm ", text)
        self.assertNotIn("yarn ", text)

        subprocess.run(["sh", "-n", str(installer)], check=True)

    def test_installer_creates_working_aegis_command_from_local_source(self) -> None:
        root = Path(__file__).resolve().parents[1]
        installer = root / "install.sh"
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            install_dir = temp_root / "install"
            bin_dir = temp_root / "bin"
            state_dir = temp_root / "state"
            env = {**os.environ, "PYTHON": sys.executable}

            subprocess.run(
                [
                    str(installer),
                    "--source",
                    str(root),
                    "--install-dir",
                    str(install_dir),
                    "--bin-dir",
                    str(bin_dir),
                    "--quiet",
                ],
                check=True,
                env=env,
                text=True,
                capture_output=True,
            )

            shim = bin_dir / "aegis"
            self.assertTrue(shim.exists())
            self.assertTrue(os.access(shim, os.X_OK))
            self.assertEqual(stat.S_IMODE(shim.stat().st_mode), 0o755)
            help_result = subprocess.run([str(shim), "--help"], check=True, text=True, capture_output=True)
            self.assertIn("Aegis Agent local-first runtime", help_result.stdout)
            health_result = subprocess.run([str(shim), "--data-dir", str(state_dir), "health"], check=True, text=True, capture_output=True)
            self.assertIn('"ok": true', health_result.stdout)


if __name__ == "__main__":
    unittest.main()
