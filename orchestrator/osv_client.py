"""
SentinelPR - OSV Vulnerability Client

Queries OSV.dev REST API or TrueForge OSV MCP Server for vulnerability data.
Zero API keys or paid tiers required.
"""

from dataclasses import dataclass, field
import json
import logging
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("sentinelpr.osv")


@dataclass
class Vulnerability:
    id: str
    cve: str
    ghsa: Optional[str]
    summary: str
    details: str
    severity: str
    fixed_versions: List[str] = field(default_factory=list)
    recommended_version: Optional[str] = None


@dataclass
class PackageScanResult:
    package: str
    ecosystem: str
    current_version: str
    vulnerable: bool
    vulnerability_count: int
    highest_severity: str
    target_fix_version: Optional[str]
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


class OSVClient:
    """Client for querying OSV.dev vulnerability intelligence."""

    def __init__(self, mcp_url: Optional[str] = None, api_base: str = "https://api.osv.dev/v1"):
        self.mcp_url = mcp_url
        self.api_base = api_base.rstrip("/")

    def _parse_severity(self, vuln: Dict[str, Any]) -> str:
        db_spec = vuln.get("database_specific", {})
        if "severity" in db_spec and db_spec["severity"]:
            return str(db_spec["severity"]).upper()

        severities = vuln.get("severity", [])
        if isinstance(severities, list):
            for s in severities:
                if s.get("type") == "CVSS_V3" and "score" in s:
                    return str(s["score"])

        return "UNKNOWN"

    def _extract_fixed_versions(self, vuln: Dict[str, Any]) -> List[str]:
        fixed = set()
        for aff in vuln.get("affected", []):
            for r in aff.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev and ev["fixed"]:
                        fixed.add(ev["fixed"])
        return sorted(list(fixed))

    def _format_vuln(self, raw: Dict[str, Any]) -> Vulnerability:
        fixed_versions = self._extract_fixed_versions(raw)
        aliases = raw.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), raw.get("id", "UNKNOWN"))
        ghsa = next((a for a in aliases if a.startswith("GHSA-")), raw.get("id") if raw.get("id", "").startswith("GHSA-") else None)
        
        summary = raw.get("summary") or (raw.get("details", "")[:150] if raw.get("details") else "No summary provided")
        
        return Vulnerability(
            id=raw.get("id", "UNKNOWN"),
            cve=cve,
            ghsa=ghsa,
            summary=summary,
            details=raw.get("details", ""),
            severity=self._parse_severity(raw),
            fixed_versions=fixed_versions,
            recommended_version=fixed_versions[0] if fixed_versions else None
        )

    def check_package(self, package_name: str, ecosystem: str = "PyPI", version: Optional[str] = None) -> PackageScanResult:
        """Query single package vulnerabilities."""
        url = f"{self.api_base}/query"
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        if version:
            payload["version"] = version

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SentinelPR-Orchestrator"}
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_vulns = data.get("vulns", [])
                vulns = [self._format_vuln(v) for v in raw_vulns]

                all_fixed = [fv for v in vulns for fv in v.fixed_versions if fv]
                target_fix = all_fixed[-1] if all_fixed else None

                return PackageScanResult(
                    package=package_name,
                    ecosystem=ecosystem,
                    current_version=version or "unknown",
                    vulnerable=len(vulns) > 0,
                    vulnerability_count=len(vulns),
                    highest_severity=vulns[0].severity if vulns else "NONE",
                    target_fix_version=target_fix,
                    vulnerabilities=vulns
                )
        except Exception as e:
            logger.error(f"Error querying OSV for {package_name}: {e}")
            raise

    def batch_check(self, dependencies: List[Dict[str, str]]) -> List[PackageScanResult]:
        """Batch query multiple dependencies."""
        if not dependencies:
            return []

        url = f"{self.api_base}/querybatch"
        queries = []
        for dep in dependencies:
            q = {
                "package": {
                    "name": dep.get("name") or dep.get("package_name"),
                    "ecosystem": dep.get("ecosystem", "PyPI")
                }
            }
            if dep.get("version"):
                q["version"] = dep["version"]
            queries.append(q)

        req = urllib.request.Request(
            url,
            data=json.dumps({"queries": queries}).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SentinelPR-Orchestrator"}
        )

        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results_data = data.get("results", [])

            results: List[PackageScanResult] = []
            for idx, item in enumerate(results_data):
                input_dep = dependencies[idx]
                raw_vulns = item.get("vulns", [])
                vulns = [self._format_vuln(v) for v in raw_vulns]

                all_fixed = [fv for v in vulns for fv in v.fixed_versions if fv]
                target_fix = all_fixed[-1] if all_fixed else None

                results.append(
                    PackageScanResult(
                        package=input_dep.get("name") or input_dep.get("package_name", ""),
                        ecosystem=input_dep.get("ecosystem", "PyPI"),
                        current_version=input_dep.get("version", "unknown"),
                        vulnerable=len(vulns) > 0,
                        vulnerability_count=len(vulns),
                        highest_severity=vulns[0].severity if vulns else "NONE",
                        target_fix_version=target_fix,
                        vulnerabilities=vulns
                    )
                )
            return results
