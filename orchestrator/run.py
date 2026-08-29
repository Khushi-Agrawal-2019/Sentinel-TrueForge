"""
SentinelPR - Main Orchestrator Loop

Coordinates manifest discovery, OSV vulnerability scanning, priority ranking,
ephemeral sandboxed verification, and GitHub Pull Request generation.
"""

from dataclasses import dataclass
import logging
from pathlib import Path
import sys
import time
from typing import Any, List, Optional

from .killswitch import KillSwitch
from .osv_client import OSVClient, PackageScanResult
from .parser import ManifestParser
from .sandbox import SandboxResult, SandboxRunner
from .template import generate_pr_body, generate_pr_title

logger = logging.getLogger("sentinelpr.orchestrator")

SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MODERATE": 2,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
    "NONE": 0
}


@dataclass
class RemediationTaskResult:
    package_name: str
    current_version: str
    target_version: str
    scan_result: PackageScanResult
    sandbox_result: SandboxResult
    pr_url: Optional[str] = None
    status: str = "PENDING"  # PASSED, FAILED, ABORTED, DRY_RUN


class Orchestrator:
    """Orchestrates the autonomous security remediation pipeline."""

    def __init__(
        self,
        repo_path: Path,
        top_n: int = 3,
        timeout: int = 180,
        dry_run: bool = True,
        github_repo: Optional[str] = None,
        github_client: Optional[Any] = None
    ):
        self.repo_path = Path(repo_path).resolve()
        self.top_n = top_n
        self.timeout = timeout
        self.dry_run = dry_run
        self.github_repo = github_repo
        self.github_client = github_client

        self.killswitch = KillSwitch(workspace_root=self.repo_path)
        self.osv = OSVClient()
        self.sandbox = SandboxRunner(
            default_timeout=self.timeout,
            killswitch_checker=self.killswitch.is_triggered,
            process_register_callback=self.killswitch.register_process
        )

    def _check_killswitch(self, stage_name: str) -> bool:
        """Checks if kill switch has been engaged and logs an alert."""
        if self.killswitch.is_triggered():
            logger.warning(f"🛑 Kill Switch is active! Aborting at stage: {stage_name}")
            print(f"\n🛑 [Kill Switch Alert] Execution halted at stage: {stage_name}. No changes were made to the repository.")
            return True
        return False

    def rank_packages(self, scan_results: List[PackageScanResult]) -> List[PackageScanResult]:
        """Ranks vulnerable packages by severity weight and vulnerability count."""
        vulnerable = [r for r in scan_results if r.vulnerable and r.target_fix_version]

        def sort_key(item: PackageScanResult):
            weight = SEVERITY_WEIGHTS.get(item.highest_severity.upper(), 0)
            return (weight, item.vulnerability_count)

        vulnerable.sort(key=sort_key, reverse=True)
        return vulnerable

    def execute(self) -> List[RemediationTaskResult]:
        """Executes the full remediation cycle."""
        print(f"\n========================================================")
        print(f"🛡️  SENTINELPR ORCHESTRATOR - AUTONOMOUS REMEDIATION LOOP")
        print(f"========================================================")
        print(f"Target Repository: {self.repo_path}")
        print(f"Top-N Fixes Limit: {self.top_n}")
        print(f"Sandbox Timeout:   {self.timeout}s")
        print(f"Execution Mode:    {'DRY-RUN (Safe Simulation)' if self.dry_run else 'LIVE PULL REQUESTS'}")
        print(f"--------------------------------------------------------\n")

        # Stage 0: Initial Killswitch Check
        if self._check_killswitch("Initialization"):
            return []

        # Stage 1: Manifest Detection & Dependency Parsing
        print("🔍 [1/5] Discovering dependency manifests...")
        manifests = ManifestParser.detect_manifests(self.repo_path)
        if not manifests:
            print("  ⚠️ No supported manifests found. Exiting.")
            return []

        deps = ManifestParser.parse_repository(self.repo_path)
        print(f"  Found {len(manifests)} manifests ({[m.name for m in manifests]}) with {len(deps)} dependencies.")

        if self._check_killswitch("Post-Manifest-Scan"):
            return []

        # Stage 2: OSV Vulnerability Scanning
        print("\n🌐 [2/5] Querying OSV.dev keyless database for vulnerability intelligence...")
        batch_query = [{"name": d.name, "ecosystem": d.ecosystem, "version": d.version} for d in deps]
        scan_results = self.osv.batch_check(batch_query)

        ranked = self.rank_packages(scan_results)
        print(f"  Identified {len(ranked)} actionable vulnerable packages with available fixes.")

        candidates = ranked[:self.top_n]
        if not candidates:
            print("  ✅ All dependencies are secure or no automated fixes are available. Done!")
            return []

        print(f"  Selected top {len(candidates)} packages for sandbox remediation:")
        for idx, c in enumerate(candidates, 1):
            print(f"    {idx}. {c.package} ({c.current_version} -> {c.target_fix_version}) [{c.highest_severity}] - {c.vulnerability_count} CVEs")

        if self._check_killswitch("Post-Scan-Ranking"):
            return []

        # Stage 3: Sandboxed Test Verification
        task_results: List[RemediationTaskResult] = []
        print("\n🧪 [3/5] Starting Sandboxed Verification...")

        for idx, candidate in enumerate(candidates, 1):
            if self._check_killswitch(f"Pre-Sandbox ({candidate.package})"):
                break

            print(f"\n--- Testing Candidate {idx}/{len(candidates)}: {candidate.package} -> {candidate.target_fix_version} ---")
            print(f"  Cloning ephemeral sandbox and applying version bump...")
            
            sandbox_res = self.sandbox.run_verification(
                repo_dir=self.repo_path,
                package_name=candidate.package,
                target_version=candidate.target_fix_version,
                timeout=self.timeout
            )

            if sandbox_res.aborted_by_killswitch:
                print(f"  🛑 Sandbox aborted by Kill Switch.")
                task_results.append(
                    RemediationTaskResult(
                        package_name=candidate.package,
                        current_version=candidate.current_version,
                        target_version=candidate.target_fix_version,
                        scan_result=candidate,
                        sandbox_result=sandbox_res,
                        status="ABORTED"
                    )
                )
                break

            if sandbox_res.passed:
                print(f"  ✅ Verification PASSED in {sandbox_res.duration_seconds:.2f}s! All tests succeeded.")
                status = "PASSED"
            else:
                print(f"  ❌ Verification FAILED (Exit Code: {sandbox_res.exit_code}) in {sandbox_res.duration_seconds:.2f}s.")
                if sandbox_res.stderr:
                    print(f"     Reason: {sandbox_res.stderr[:200]}")
                print(f"     ⚠️ PR will NOT be opened for {candidate.package} to preserve repository safety.")
                status = "FAILED"

            task_results.append(
                RemediationTaskResult(
                    package_name=candidate.package,
                    current_version=candidate.current_version,
                    target_version=candidate.target_fix_version,
                    scan_result=candidate,
                    sandbox_result=sandbox_res,
                    status=status
                )
            )

        # Stage 4: PR Creation or Dry-Run Reporting
        print("\n📦 [4/5] Processing Remediation Pull Requests...")
        for res in task_results:
            if res.status != "PASSED":
                continue

            if self._check_killswitch(f"Pre-PR ({res.package_name})"):
                break

            pr_title = generate_pr_title(res.package_name, res.current_version, res.target_version)
            pr_body = generate_pr_body(res.scan_result, res.sandbox_result, target_repo=self.github_repo)

            if self.dry_run or not self.github_client:
                print(f"\n[DRY RUN - Safe Simulation] PR Proposal for {res.package_name}:")
                print(f"Title: {pr_title}")
                print(f"Evidence: {res.sandbox_result.duration_seconds:.2f}s test run passed cleanly.")
                print(f"Target Branch: sentinelpr/fix-{res.package_name}-{res.target_version}")
                res.status = "DRY_RUN"
            else:
                print(f"\n🚀 Opening verified GitHub PR for {res.package_name}...")
                try:
                    pr_url = self.github_client.create_pull_request(
                        repo_dir=self.repo_path,
                        package_name=res.package_name,
                        current_version=res.current_version,
                        target_version=res.target_version,
                        title=pr_title,
                        body=pr_body
                    )
                    res.pr_url = pr_url
                    res.status = "PR_OPENED"
                    print(f"  🎉 PR successfully created: {pr_url}")
                except Exception as e:
                    logger.error(f"Failed to open PR for {res.package_name}: {e}")
                    res.status = "PR_FAILED"

        # Stage 5: Final Summary
        print("\n📊 [5/5] Final Remediation Summary:")
        print("=" * 80)
        print(f"{'PACKAGE':<18} {'UPGRADE':<24} {'SANDBOX':<12} {'RESULT':<20}")
        print("-" * 80)
        for r in task_results:
            upgrade_str = f"{r.current_version} -> {r.target_version}"
            sandbox_status = "✅ PASS" if r.sandbox_result.passed else "❌ FAIL"
            print(f"{r.package_name:<18} {upgrade_str:<24} {sandbox_status:<12} {r.status:<20}")
        print("=" * 80 + "\n")

        return task_results
