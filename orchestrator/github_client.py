"""
SentinelPR - Safe GitHub Integration Client

Handles branch creation, isolated file commits, and Pull Request generation
via the GitHub REST API. Enforces strict safety rules: NEVER pushes to default/main.
"""

import base64
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import subprocess
from typing import Dict, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("sentinelpr.github")


class GitHubClient:
    """Safe GitHub API client for automated PR creation."""

    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None):
        self.token = token or self._detect_token()
        self.repo = repo
        self.api_base = "https://api.github.com"

    def _detect_token(self) -> Optional[str]:
        """Discovers GitHub token from environment or macOS keychain."""
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            return token

        # Attempt to retrieve from keychain
        try:
            proc = subprocess.run(
                ["git", "credential-osxkeychain", "get"],
                input=b"host=github.com\nprotocol=https\n",
                capture_output=True,
                timeout=3
            )
            if proc.returncode == 0:
                lines = proc.stdout.decode().splitlines()
                creds = dict(l.split("=", 1) for l in lines if "=" in l)
                return creds.get("password")
        except Exception:
            pass
        return None

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        if not self.token:
            raise ValueError("No GitHub token provided or detected.")

        url = f"{self.api_base}/{endpoint.lstrip('/')}"
        headers = {
            "Authorization": f"token {self.token}",
            "User-Agent": "SentinelPR-Agent",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }

        body_bytes = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 204:
                    return {}
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            logger.error(f"GitHub API Error [{e.code}] {method} {url}: {err_body}")
            raise RuntimeError(f"GitHub API Error [{e.code}]: {err_body}")

    def get_repo_details(self, repo: str) -> Dict:
        """Fetch repository details including default branch."""
        return self._request("GET", f"/repos/{repo}")

    def create_pull_request(
        self,
        repo_dir: Path,
        package_name: str,
        current_version: str,
        target_version: str,
        title: str,
        body: str,
        target_repo: Optional[str] = None
    ) -> str:
        """
        Creates a dedicated security branch, commits the version bump, and opens a PR.
        Returns the HTML URL of the created pull request.
        """
        repo_name = target_repo or self.repo
        if not repo_name:
            raise ValueError("Target GitHub repository ('owner/repo') not specified.")

        repo_info = self.get_repo_details(repo_name)
        default_branch = repo_info.get("default_branch", "main")

        # 1. Get default branch latest commit SHA
        ref_data = self._request("GET", f"/repos/{repo_name}/git/ref/heads/{default_branch}")
        base_sha = ref_data["object"]["sha"]

        # 2. Create new branch
        branch_name = f"sentinelpr/fix-{package_name}-{target_version}"
        try:
            self._request("POST", f"/repos/{repo_name}/git/refs", {
                "ref": f"refs/heads/{branch_name}",
                "sha": base_sha
            })
            logger.info(f"Created branch {branch_name} on {repo_name}")
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.info(f"Branch {branch_name} already exists, updating ref.")
            else:
                raise

        # 3. Apply version bump to file content via GitHub Contents API
        # Look for manifest file
        for manifest_name in ["requirements.txt", "package.json"]:
            try:
                file_info = self._request("GET", f"/repos/{repo_name}/contents/{manifest_name}?ref={branch_name}")
                file_sha = file_info["sha"]
                content_b64 = file_info["content"]
                raw_content = base64.b64decode(content_b64).decode("utf-8")

                # Perform safe version replacement
                new_content = None
                if manifest_name == "requirements.txt":
                    import re
                    pattern = re.compile(rf"^{re.escape(package_name)}\s*(==|>=|<=|~=|!=)?.*$", re.IGNORECASE | re.MULTILINE)
                    if pattern.search(raw_content):
                        new_content = pattern.sub(f"{package_name}=={target_version}", raw_content)
                elif manifest_name == "package.json":
                    try:
                        pkg_json = json.loads(raw_content)
                        for sec in ["dependencies", "devDependencies"]:
                            if sec in pkg_json and package_name in pkg_json[sec]:
                                pkg_json[sec][package_name] = target_version
                        new_content = json.dumps(pkg_json, indent=2) + "\n"
                    except Exception:
                        pass

                if new_content and new_content != raw_content:
                    # Update file in branch
                    self._request("PUT", f"/repos/{repo_name}/contents/{manifest_name}", {
                        "message": f"fix(deps): bump {package_name} from {current_version} to {target_version}",
                        "content": base64.b64encode(new_content.encode("utf-8")).decode("utf-8"),
                        "sha": file_sha,
                        "branch": branch_name
                    })
                    logger.info(f"Committed dependency bump to {manifest_name} on {branch_name}")
                    break
            except Exception as e:
                logger.debug(f"Manifest {manifest_name} not found or skipped on {repo_name}: {e}")

        # 4. Open Pull Request
        pr_data = self._request("POST", f"/repos/{repo_name}/pulls", {
            "title": title,
            "head": branch_name,
            "base": default_branch,
            "body": body
        })

        pr_url = pr_data.get("html_url")
        logger.info(f"Successfully opened Pull Request #{pr_data.get('number')}: {pr_url}")
        return pr_url
