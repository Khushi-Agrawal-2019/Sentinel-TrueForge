"""
Unit tests for SentinelPR Sandbox Runner and Manifest Parser.
"""

from pathlib import Path
import tempfile
import unittest

from orchestrator.parser import ManifestParser
from orchestrator.sandbox import SandboxRunner


class TestSandboxRunner(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "demo-repo-fixtures"
        self.python_demo = self.fixtures_dir / "python-demo"
        self.node_demo = self.fixtures_dir / "node-demo"
        self.runner = SandboxRunner(default_timeout=30)

    def test_parse_python_manifest(self):
        """Verify python requirements.txt parsing."""
        deps = ManifestParser.parse_requirements_txt(self.python_demo / "requirements.txt")
        dep_map = {d.name: d.version for d in deps}
        self.assertIn("jinja2", dep_map)
        self.assertEqual(dep_map["jinja2"], "2.11.2")
        self.assertIn("requests", dep_map)
        self.assertEqual(dep_map["requests"], "2.25.1")

    def test_parse_node_manifest(self):
        """Verify node package.json parsing."""
        deps = ManifestParser.parse_package_json(self.node_demo / "package.json")
        dep_map = {d.name: d.version for d in deps}
        self.assertIn("lodash", dep_map)
        self.assertEqual(dep_map["lodash"], "4.17.15")

    def test_sandbox_python_verification_success(self):
        """Verify running tests on python demo fixture with bumped dependency in sandbox."""
        result = self.runner.run_verification(
            repo_dir=self.python_demo,
            package_name="jinja2",
            target_version="3.1.5"
        )
        self.assertTrue(result.passed, f"Sandbox test failed: {result.stderr}")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("OK", result.stderr + result.stdout)

    def test_sandbox_node_verification_success(self):
        """Verify running tests on node demo fixture in sandbox."""
        result = self.runner.run_verification(
            repo_dir=self.node_demo,
            package_name="lodash",
            target_version="4.17.21"
        )
        self.assertTrue(result.passed, f"Sandbox test failed: {result.stderr}")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("All Node fixture tests passed", result.stdout)

    def test_sandbox_timeout_enforcement(self):
        """Verify sandbox cleanly aborts commands that exceed the wall-clock timeout."""
        runner_short = SandboxRunner(default_timeout=1)
        result = runner_short.run_verification(
            repo_dir=self.python_demo,
            package_name="jinja2",
            target_version="3.1.5",
            timeout=1,
            custom_test_cmd=["python3", "-c", "import time; time.sleep(5)"]
        )
        self.assertFalse(result.passed)
        self.assertIn("timed out", result.stderr.lower())

    def test_original_repo_untouched(self):
        """Confirm that the original requirements.txt was NEVER modified."""
        content = (self.python_demo / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("jinja2==2.11.2", content)


if __name__ == "__main__":
    unittest.main()
