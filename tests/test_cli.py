from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from aegis.cli.main import create_skill_template, dispatch, build_parser


class CliTests(unittest.TestCase):
    def test_skill_create_template_is_disabled_and_approval_required(self) -> None:
        manifest = create_skill_template("example.skill", name="Example", description="Example skill")

        self.assertEqual(manifest["id"], "example.skill")
        self.assertEqual(manifest["risk_level"], "medium")
        self.assertTrue(manifest["approval_required"])
        self.assertEqual(manifest["sandbox_profile"], "no_tools")

    def test_dashboard_command_reports_product_posture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parser = build_parser()
            args = parser.parse_args(["--data-dir", str(Path(temp) / ".aegis"), "dashboard"])
            result = dispatch(args)

            self.assertEqual(result["product"]["name"], "Aegis Agent")
            self.assertIn("security_controls", result)
            self.assertGreaterEqual(result["runtime"]["tools"], 47)


if __name__ == "__main__":
    unittest.main()
