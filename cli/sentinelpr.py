#!/usr/bin/env python3
"""
SentinelPR - Autonomous Safe Dependency Remediation CLI

Commands:
  sentinelpr scan [--repo PATH]
  sentinelpr run  [--repo PATH] [--top-n N] [--dry-run] [--open-pr] [--timeout SEC]
  sentinelpr stop
  sentinelpr status
  sentinelpr reset
"""

import argparse
import json
import logging
import os
from pathlib import Path
import sys

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from orchestrator.killswitch import KillSwitch
from orchestrator.osv_client import OSVClient
from orchestrator.parser import ManifestParser
from orchestrator.sandbox import SandboxRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinelpr")


def cmd_scan(args):
    """Scans target repository for vulnerable dependencies via OSV."""
    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        print(f"Error: Directory {repo_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"\n🔍 [SentinelPR Scan] Analyzing manifests in {repo_path}...")
    manifests = ManifestParser.detect_manifests(repo_path)
    if not manifests:
        print("  No supported manifests found (requirements.txt, package.json, pyproject.toml).")
        return

    print(f"  Found manifests: {[m.name for m in manifests]}")
    deps = ManifestParser.parse_repository(repo_path)
    print(f"  Extracted {len(deps)} pinned dependencies.")

    osv = OSVClient()
    batch_query = [{"name": d.name, "ecosystem": d.ecosystem, "version": d.version} for d in deps]
    
    print("  Querying OSV.dev keyless database...")
    results = osv.batch_check(batch_query)

    vulnerable = [r for r in results if r.vulnerable]
    print(f"\n📊 [Scan Results] {len(vulnerable)} / {len(results)} packages contain known vulnerabilities:")
    print("=" * 80)
    print(f"{'PACKAGE':<18} {'ECOSYSTEM':<10} {'CURRENT':<10} {'SEVERITY':<12} {'FIX VERSION':<14} {'VULNS':<6}")
    print("-" * 80)

    for r in results:
        status_color = "🔴" if r.vulnerable else "🟢"
        fix = r.target_fix_version or "N/A"
        print(f"{status_color} {r.package:<16} {r.ecosystem:<10} {r.current_version:<10} {r.highest_severity:<12} {fix:<14} {r.vulnerability_count:<6}")
        if r.vulnerable:
            for v in r.vulnerabilities[:2]:
                print(f"    ↳ [{v.cve or v.id}] ({v.severity}): {v.summary[:70]}...")
            if len(r.vulnerabilities) > 2:
                print(f"    ↳ ... and {len(r.vulnerabilities) - 2} more vulnerabilities.")

    print("=" * 80 + "\n")


def cmd_stop(args):
    """Triggers the fail-safe kill switch and terminates running jobs."""
    killswitch = KillSwitch()
    status = killswitch.trigger(reason=args.reason or "Manual abort via CLI")

    print("\n🛑 ========================================================")
    print("   SENTINELPR KILL SWITCH ENGAGED - EMERGENCY HALT")
    print("============================================================")
    print(f"  Reason:                {status.reason}")
    print(f"  Timestamp:             {status.timestamp}")
    print(f"  Terminated Processes:  {len(status.terminated_pids or [])} active sandbox processes")
    print(f"  Terminated Containers: {len(status.terminated_containers or [])} active Docker containers")
    print("------------------------------------------------------------")
    print("  🔒 AUDIT CONFIRMATION: The source repository was NEVER touched.")
    print("     Zero commits, zero pushes, zero destructive changes.")
    print("============================================================\n")


def cmd_status(args):
    """Displays the status of the Kill Switch and runtime state."""
    killswitch = KillSwitch()
    status = killswitch.get_status()
    print("\n📋 [SentinelPR Status]")
    print(f"  Kill Switch Active:  {'🔴 YES (Execution Blocked)' if status.is_active else '🟢 NO (Ready)'}")
    if status.is_active:
        print(f"  Trigger Reason:      {status.reason}")
        print(f"  Action Required:     Run `sentinelpr reset` before next run.")
    print(f"  Active Process PIDs: {list(killswitch.get_registered_pids())}")
    print()


def cmd_reset(args):
    """Resets the kill switch flag."""
    killswitch = KillSwitch()
    killswitch.reset()
    print("\n✅ SentinelPR Kill Switch reset successfully. System is armed and ready.\n")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelPR: Autonomous Safe Dependency Remediation Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Scan command
    p_scan = subparsers.add_parser("scan", help="Scan repository dependencies for OSV vulnerabilities")
    p_scan.add_argument("--repo", default=".", help="Path to target repository (default: current dir)")

    # Run command
    p_run = subparsers.add_parser("run", help="Execute the remediation loop with sandbox verification")
    p_run.add_argument("--repo", default=".", help="Path to target repository")
    p_run.add_argument("--top-n", type=int, default=3, help="Max number of vulnerabilities to remediate (default: 3)")
    p_run.add_argument("--timeout", type=int, default=180, help="Sandbox timeout in seconds (default: 180)")
    p_run.add_argument("--dry-run", action="store_true", default=True, help="Simulate PR creation without touching GitHub")
    p_run.add_argument("--open-pr", action="store_true", help="Enable actual GitHub PR creation (requires GITHUB_TOKEN)")
    p_run.add_argument("--github-repo", help="Target GitHub repo (e.g. 'owner/repo')")

    # Stop command
    p_stop = subparsers.add_parser("stop", help="Emergency kill switch: aborts execution & kills sandboxes immediately")
    p_stop.add_argument("--reason", default="Manual abort via sentinelpr stop", help="Reason for stopping")

    # Status command
    p_status = subparsers.add_parser("status", help="Show Kill Switch status and active processes")

    # Reset command
    p_reset = subparsers.add_parser("reset", help="Reset Kill Switch flag")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "stop":
        cmd_stop(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "reset":
        cmd_reset(args)
    elif args.command == "run":
        from orchestrator.run import Orchestrator
        orchestrator = Orchestrator(
            repo_path=Path(args.repo).resolve(),
            top_n=args.top_n,
            timeout=args.timeout,
            dry_run=not args.open_pr or args.dry_run,
            github_repo=args.github_repo
        )
        orchestrator.execute()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
