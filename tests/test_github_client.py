"""
Unit tests for SentinelPR GitHub Client.
"""

from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from orchestrator.github_client import GitHubClient


class TestGitHubClient(unittest.TestCase):

    def test_token_discovery_mock(self):
        """Verify token discovery from explicit parameter."""
        client = GitHubClient(token="mock_test_token_123", repo="test-owner/test-repo")
        self.assertEqual(client.token, "mock_test_token_123")
        self.assertEqual(client.repo, "test-owner/test-repo")

    @patch("orchestrator.github_client.urllib.request.urlopen")
    def test_create_pull_request_flow(self, mock_urlopen):
        """Verify the full branch creation, file update, and PR opening API sequence."""
        client = GitHubClient(token="mock_token", repo="owner/repo")

        # Mock API responses:
        # 1. GET /repos/owner/repo -> default branch info
        # 2. GET /repos/owner/repo/git/ref/heads/main -> base sha
        # 3. POST /repos/owner/repo/git/refs -> branch created
        # 4. GET /repos/owner/repo/contents/requirements.txt -> file info
        # 5. PUT /repos/owner/repo/contents/requirements.txt -> updated file
        # 6. POST /repos/owner/repo/pulls -> PR created

        mock_responses = [
            {"default_branch": "main"},
            {"object": {"sha": "base_sha_abc123"}},
            {"ref": "refs/heads/sentinelpr/fix-jinja2-3.1.5"},
            {"sha": "file_sha_xyz", "content": "amluamEyPT0yLjExLjIK"},  # base64 for "jinja2==2.11.2\n"
            {"content": {"name": "requirements.txt"}},
            {"number": 42, "html_url": "https://github.com/owner/repo/pull/42"}
        ]

        def side_effect(req, timeout=15):
            mock_resp = MagicMock()
            import json
            data = mock_responses.pop(0)
            mock_resp.read.return_value = json.dumps(data).encode("utf-8")
            mock_resp.status = 200
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp

        mock_urlopen.side_effect = side_effect

        pr_url = client.create_pull_request(
            repo_dir=Path("/tmp"),
            package_name="jinja2",
            current_version="2.11.2",
            target_version="3.1.5",
            title="Fix jinja2",
            body="PR Body"
        )

        self.assertEqual(pr_url, "https://github.com/owner/repo/pull/42")


if __name__ == "__main__":
    unittest.main()
