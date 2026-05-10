from __future__ import annotations

import unittest

from aegis.cli.main import create_skill_template


class CliTests(unittest.TestCase):
    def test_skill_create_template_is_disabled_and_approval_required(self) -> None:
        manifest = create_skill_template("example.skill", name="Example", description="Example skill")

        self.assertEqual(manifest["id"], "example.skill")
        self.assertEqual(manifest["risk_level"], "medium")
        self.assertTrue(manifest["approval_required"])
        self.assertEqual(manifest["sandbox_profile"], "no_tools")


if __name__ == "__main__":
    unittest.main()
