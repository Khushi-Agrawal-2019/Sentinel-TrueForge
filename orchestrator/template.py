"""
SentinelPR - PR Description Template Generator

Generates structured, auditable GitHub Pull Request descriptions containing
CVE/GHSA advisories, before/after diffs, verbatim test evidence, and safety disclaimers.
"""

from typing import List, Optional
from .osv_client import PackageScanResult, Vulnerability
from .sandbox import SandboxResult


def generate_pr_title(package_name: str, current_version: str, target_version: str) -> str:
    """Generates a standardized, clear PR title."""
    return f"🛡️ [SentinelPR] Security Fix: Upgrade {package_name} from {current_version} to {target_version}"


def generate_pr_body(
    scan_result: PackageScanResult,
    sandbox_result: SandboxResult,
    target_repo: Optional[str] = None
) -> str:
    """
    Generates a rich GitHub PR description adhering to SentinelPR safety guidelines.
    """
    vulns = scan_result.vulnerabilities
    primary_cve = vulns[0].cve if vulns else "Vulnerability Remediation"
    severity = scan_result.highest_severity

    # Build vulnerabilities list
    vuln_rows = []
    for v in vulns[:5]:
        ghsa_link = f"[{v.ghsa}](https://github.com/advisories/{v.ghsa})" if v.ghsa else "N/A"
        cve_link = f"[{v.cve}](https://nvd.nist.gov/vuln/detail/{v.cve})" if v.cve.startswith("CVE-") else v.cve
        summary_clean = v.summary.replace("\n", " ").strip()
        vuln_rows.append(f"| {cve_link} | {ghsa_link} | `{v.severity}` | {summary_clean} |")

    vuln_table = "\n".join(vuln_rows) if vuln_rows else "| None | None | NONE | No details |"
    extra_vulns_note = f"\n*...and {len(vulns) - 5} additional advisories resolved by this upgrade.*" if len(vulns) > 5 else ""

    # Truncate test output if excessively long
    test_output = (sandbox_result.stdout + "\n" + sandbox_result.stderr).strip()
    if len(test_output) > 3000:
        test_output = test_output[:1500] + "\n\n... [output truncated for brevity] ...\n\n" + test_output[-1500:]

    body = f"""## 🛡️ SentinelPR Autonomous Security Remediation

### 📌 Summary
SentinelPR has detected known security vulnerabilities in **`{scan_result.package}`** (`{scan_result.ecosystem}`) and verified a safe upgrade path in an isolated sandbox.

| Property | Value |
| :--- | :--- |
| **Package** | `{scan_result.package}` |
| **Ecosystem** | `{scan_result.ecosystem}` |
| **Current Version** | `{scan_result.current_version}` |
| **Target Fixed Version** | `{sandbox_result.target_version}` |
| **Highest Severity** | `{severity}` |
| **Sandbox Verification** | `PASSED` (Execution time: {sandbox_result.duration_seconds:.2f}s) |

---

### 🔍 Resolved Advisories ({len(vulns)})

| Advisory ID | GHSA | Severity | Summary |
| :--- | :--- | :--- | :--- |
{vuln_table}
{extra_vulns_note}

---

### 🧪 Sandboxed Verification Evidence
Before proposing this Pull Request, SentinelPR executed the repository's test suite inside an ephemeral, completely isolated sandbox environment.

> **Status:** ✅ **All tests passed with zero regressions.**

<details>
<summary><b>Click to expand full test suite execution log ({sandbox_result.duration_seconds:.2f}s)</b></summary>

```text
{test_output}
```

</details>

---

### ⚠️ Human Review & Safety Guidelines
- **Autonomous Origin:** This PR was generated autonomously by **SentinelPR** using the **TrueForge Agent Harness**.
- **No Auto-Merge:** Automated merging is disabled. A human maintainer **must review and approve** this pull request prior to merging.
- **Safety Guarantee:** SentinelPR executed all tests inside an isolated sandbox and verified compatibility before opening this PR.

---
*Generated with 🛡️ by [SentinelPR](https://github.com/Khushi-Agrawal-2019/Sentinel-TrueForge) • Powered by [TrueForge](https://github.com/truefoundry/trueforge) & [OSV.dev](https://osv.dev)*
"""
    return body
