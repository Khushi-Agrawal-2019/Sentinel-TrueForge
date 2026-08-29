"""
Unit tests for OSV Client and MCP Tool Integration.
"""

import unittest
from orchestrator.osv_client import OSVClient


class TestOSVMCPClient(unittest.TestCase):

    def setUp(self):
        self.client = OSVClient()

    def test_single_vulnerable_package_pypi(self):
        """Test checking jinja2 2.11.2 (known vulnerable) resolves to 3.1.6 patch release."""
        result = self.client.check_package("jinja2", ecosystem="PyPI", version="2.11.2")
        self.assertTrue(result.vulnerable)
        self.assertGreater(result.vulnerability_count, 0)
        self.assertEqual(result.target_fix_version, "3.1.6")
        self.assertTrue(any(v.cve for v in result.vulnerabilities))

    def test_semver_sorting(self):
        """Verify _parse_semver handles mixed versions, patches, and pre-releases correctly."""
        versions = ["2.11.3", "3.1.5", "3.1.6", "3.1.3", "3.1.4", "1.26.4", "2.5.0"]
        sorted_vers = sorted(versions, key=self.client._parse_semver)
        self.assertEqual(sorted_vers[-1], "3.1.6")
        self.assertEqual(sorted_vers[0], "1.26.4")

    def test_single_vulnerable_package_npm(self):
        """Test checking lodash 4.17.15 (known vulnerable npm package)."""
        result = self.client.check_package("lodash", ecosystem="npm", version="4.17.15")
        self.assertTrue(result.vulnerable)
        self.assertGreater(result.vulnerability_count, 0)

    def test_batch_check_dependencies(self):
        """Test batch query for multiple dependencies."""
        deps = [
            {"name": "jinja2", "ecosystem": "PyPI", "version": "2.11.2"},
            {"name": "requests", "ecosystem": "PyPI", "version": "2.25.1"},
            {"name": "pytest", "ecosystem": "PyPI", "version": "8.0.0"}
        ]
        results = self.client.batch_check(deps)
        self.assertEqual(len(results), 3)
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        self.assertGreaterEqual(vulnerable_count, 2)


if __name__ == "__main__":
    unittest.main()
