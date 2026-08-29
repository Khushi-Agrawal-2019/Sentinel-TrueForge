"""
Unit test suite for Python Demo Fixture.
Verifies application functions correctly with pinned or upgraded dependencies.
"""

import unittest
from app import render_greeting, format_status


class TestDemoApp(unittest.TestCase):

    def test_greeting_rendering(self):
        output = render_greeting("Alice")
        self.assertIn("Hello, Alice!", output)
        self.assertIn("SentinelPR Secure App", output)

    def test_status_formatting_success(self):
        status = format_status(200)
        self.assertTrue(status["is_success"])
        self.assertEqual(status["status"], 200)

    def test_status_formatting_failure(self):
        status = format_status(500)
        self.assertFalse(status["is_success"])
        self.assertEqual(status["status"], 500)


if __name__ == "__main__":
    unittest.main()
