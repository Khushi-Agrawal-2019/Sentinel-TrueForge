/**
 * Standalone test suite for OSV MCP Server.
 * Validates check_vulnerabilities and batch_check against known vulnerabilities.
 */

import { checkVulnerabilities, batchCheck, buildServer } from "./server.mjs";

async function runTests() {
  console.log("=== Testing OSV MCP Server (Standalone) ===\n");
  let passed = 0;
  let failed = 0;

  // Test 1: Single package check (Jinja2 2.11.2 - known vulnerable)
  try {
    console.log("[Test 1] Checking known vulnerable package: jinja2 2.11.2 (PyPI)...");
    const result = await checkVulnerabilities({
      package_name: "jinja2",
      ecosystem: "PyPI",
      version: "2.11.2"
    });

    if (result.vulnerable && result.vulnerability_count > 0 && result.target_fix_version) {
      console.log(`  ✓ Passed: Found ${result.vulnerability_count} vulnerabilities, Target fix: ${result.target_fix_version}`);
      console.log(`  ✓ Sample CVE: ${result.vulnerabilities[0].cve} | Severity: ${result.vulnerabilities[0].severity}`);
      passed++;
    } else {
      console.error("  ✗ Failed: Expected vulnerabilities for jinja2 2.11.2, got:", result);
      failed++;
    }
  } catch (err) {
    console.error("  ✗ Test 1 Error:", err);
    failed++;
  }

  // Test 2: Single package check (npm package: lodash 4.17.15 - Prototype Pollution)
  try {
    console.log("\n[Test 2] Checking known vulnerable package: lodash 4.17.15 (npm)...");
    const result = await checkVulnerabilities({
      package_name: "lodash",
      ecosystem: "npm",
      version: "4.17.15"
    });

    if (result.vulnerable && result.vulnerability_count > 0) {
      console.log(`  ✓ Passed: Found ${result.vulnerability_count} vulnerabilities for lodash 4.17.15`);
      passed++;
    } else {
      console.error("  ✗ Failed: Expected vulnerabilities for lodash 4.17.15, got:", result);
      failed++;
    }
  } catch (err) {
    console.error("  ✗ Test 2 Error:", err);
    failed++;
  }

  // Test 3: Batch check with multiple dependencies
  try {
    console.log("\n[Test 3] Batch checking dependencies: jinja2, requests, pytest...");
    const batchResult = await batchCheck({
      dependencies: [
        { name: "jinja2", ecosystem: "PyPI", version: "2.11.2" },
        { name: "requests", ecosystem: "PyPI", version: "2.25.1" },
        { name: "pytest", ecosystem: "PyPI", version: "8.0.0" }
      ]
    });

    if (batchResult.scanned_count === 3 && batchResult.vulnerable_packages_count >= 2) {
      console.log(`  ✓ Passed: Scanned ${batchResult.scanned_count} packages, found ${batchResult.vulnerable_packages_count} vulnerable packages, total vulns: ${batchResult.total_vulnerabilities}`);
      passed++;
    } else {
      console.error("  ✗ Failed: Unexpected batch result:", batchResult);
      failed++;
    }
  } catch (err) {
    console.error("  ✗ Test 3 Error:", err);
    failed++;
  }

  // Test 4: Verify McpServer registration
  try {
    console.log("\n[Test 4] Verifying MCP server registration and tools...");
    const server = buildServer();
    if (server) {
      console.log("  ✓ Passed: McpServer successfully constructed with tool definitions.");
      passed++;
    }
  } catch (err) {
    console.error("  ✗ Test 4 Error:", err);
    failed++;
  }

  console.log(`\n========================================`);
  console.log(`Summary: ${passed} passed, ${failed} failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
