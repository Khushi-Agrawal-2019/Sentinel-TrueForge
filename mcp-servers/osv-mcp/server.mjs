/**
 * SentinelPR - OSV.dev Model Context Protocol (MCP) Server
 * 
 * Provides automated, keyless vulnerability intelligence using the free OSV.dev REST API.
 * Compatible with TrueForge HTTP MCP transport and standalone JSON-RPC.
 */

/* global fetch, AbortSignal */
import express from "express";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const PORT = Number(process.env.OSV_MCP_PORT || 8950);
const OSV_API_BASE = "https://api.osv.dev/v1";

/**
 * Normalizes severity score from OSV response or CVSS string.
 */
function parseSeverity(vuln) {
  if (vuln.database_specific?.severity) {
    return vuln.database_specific.severity.toUpperCase();
  }
  if (vuln.severity && Array.isArray(vuln.severity)) {
    for (const sev of vuln.severity) {
      if (sev.type === "CVSS_V3" && sev.score) {
        return sev.score;
      }
    }
  }
  return "UNKNOWN";
}

/**
 * Extracts minimum fixed versions from affected ranges.
 */
function extractFixedVersions(vuln, currentVersion) {
  const fixedVersions = new Set();
  const affected = vuln.affected || [];
  
  for (const item of affected) {
    const ranges = item.ranges || [];
    for (const range of ranges) {
      const events = range.events || [];
      for (const event of events) {
        if (event.fixed) {
          fixedVersions.add(event.fixed);
        }
      }
    }
  }

  const sortedFixed = Array.from(fixedVersions);
  return {
    fixed_versions: sortedFixed,
    recommended_version: sortedFixed.length > 0 ? sortedFixed[0] : null
  };
}

/**
 * Formats a raw OSV vulnerability into a clean, structured object.
 */
function formatVulnerability(vuln, currentVersion) {
  const { fixed_versions, recommended_version } = extractFixedVersions(vuln, currentVersion);
  
  // Extract aliases (CVEs, GHSAs)
  const aliases = vuln.aliases || [];
  const cve = aliases.find(a => a.startsWith("CVE-")) || vuln.id;
  const ghsa = aliases.find(a => a.startsWith("GHSA-")) || (vuln.id.startsWith("GHSA-") ? vuln.id : null);

  return {
    id: vuln.id,
    cve,
    ghsa,
    summary: vuln.summary || vuln.details?.slice(0, 150) || "No summary provided",
    details: vuln.details || "",
    severity: parseSeverity(vuln),
    published: vuln.published,
    modified: vuln.modified,
    fixed_versions,
    recommended_version
  };
}

/**
 * Query OSV.dev for a single package.
 */
export async function checkVulnerabilities({ package_name, ecosystem = "PyPI", version }) {
  const payload = {
    package: {
      name: package_name,
      ecosystem: ecosystem
    }
  };

  if (version) {
    payload.version = version;
  }

  const response = await fetch(`${OSV_API_BASE}/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15000)
  });

  if (!response.ok) {
    throw new Error(`OSV API returned status ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const rawVulns = data.vulns || [];
  const formattedVulns = rawVulns.map(v => formatVulnerability(v, version));

  // Determine highest recommended fixed version across all discovered vulns
  const allFixed = formattedVulns.flatMap(v => v.fixed_versions).filter(Boolean);
  const targetFix = allFixed.length > 0 ? allFixed[allFixed.length - 1] : null;

  return {
    package: package_name,
    ecosystem,
    current_version: version || "unknown",
    vulnerable: formattedVulns.length > 0,
    vulnerability_count: formattedVulns.length,
    highest_severity: formattedVulns.length > 0 ? formattedVulns[0].severity : "NONE",
    target_fix_version: targetFix,
    vulnerabilities: formattedVulns
  };
}

/**
 * Query OSV.dev batch endpoint for multiple packages simultaneously.
 */
export async function batchCheck({ dependencies }) {
  if (!Array.isArray(dependencies) || dependencies.length === 0) {
    return { results: [], total_vulnerabilities: 0 };
  }

  const queries = dependencies.map(dep => ({
    package: {
      name: dep.name || dep.package_name,
      ecosystem: dep.ecosystem || "PyPI"
    },
    ...(dep.version ? { version: dep.version } : {})
  }));

  const response = await fetch(`${OSV_API_BASE}/querybatch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(20000)
  });

  if (!response.ok) {
    throw new Error(`OSV Batch API returned status ${response.status}: ${await response.text()}`);
  }

  const data = await response.json();
  const batchResults = data.results || [];

  let totalVulns = 0;
  const processed = batchResults.map((item, idx) => {
    const inputDep = dependencies[idx];
    const rawVulns = item.vulns || [];
    const formattedVulns = rawVulns.map(v => formatVulnerability(v, inputDep.version));
    totalVulns += formattedVulns.length;

    const allFixed = formattedVulns.flatMap(v => v.fixed_versions).filter(Boolean);
    const targetFix = allFixed.length > 0 ? allFixed[allFixed.length - 1] : null;

    return {
      package: inputDep.name || inputDep.package_name,
      ecosystem: inputDep.ecosystem || "PyPI",
      current_version: inputDep.version || "unknown",
      vulnerable: formattedVulns.length > 0,
      vulnerability_count: formattedVulns.length,
      highest_severity: formattedVulns.length > 0 ? formattedVulns[0].severity : "NONE",
      target_fix_version: targetFix,
      vulnerabilities: formattedVulns
    };
  });

  return {
    scanned_count: dependencies.length,
    vulnerable_packages_count: processed.filter(p => p.vulnerable).length,
    total_vulnerabilities: totalVulns,
    results: processed
  };
}

/**
 * Builds the MCP Server instance with tool definitions.
 */
export function buildServer() {
  const server = new McpServer(
    { name: "osv-vulnerability-scanner", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.registerTool(
    "check_vulnerabilities",
    {
      title: "Check Package Vulnerabilities",
      description: "Queries OSV.dev for known security vulnerabilities (CVEs, GHSAs) and minimum fixed versions for a given package and ecosystem.",
      inputSchema: {
        package_name: z.string().min(1).describe("The package name (e.g. 'jinja2', 'requests', 'express')"),
        ecosystem: z.string().default("PyPI").describe("Package ecosystem (e.g. 'PyPI', 'npm', 'Maven', 'Go')"),
        version: z.string().optional().describe("Specific pinned version (e.g. '2.11.2')")
      }
    },
    async (args) => {
      try {
        const result = await checkVulnerabilities(args);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({ error: err.message }) }]
        };
      }
    }
  );

  server.registerTool(
    "batch_check",
    {
      title: "Batch Check Dependencies",
      description: "Scans an entire list of repository dependencies against OSV.dev in one request.",
      inputSchema: {
        dependencies: z.array(
          z.object({
            name: z.string().describe("Package name"),
            ecosystem: z.string().default("PyPI").describe("Ecosystem (e.g. 'PyPI', 'npm')"),
            version: z.string().optional().describe("Installed package version")
          })
        ).describe("Array of dependency objects")
      }
    },
    async (args) => {
      try {
        const result = await batchCheck(args);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({ error: err.message }) }]
        };
      }
    }
  );

  return server;
}

// HTTP Server setup for TrueForge compatibility
const app = express();
app.use(express.json({ limit: "4mb" }));

app.get("/", (_req, res) => {
  res.type("text/plain").send("SentinelPR OSV MCP Server. POST MCP JSON-RPC requests to /mcp.");
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "osv-mcp", port: PORT });
});

app.post("/mcp", async (req, res) => {
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("[osv-mcp] Error handling request:", err?.message || err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: req.body?.id || null
      });
    }
  }
});

if (process.argv[1] && process.argv[1].endsWith("server.mjs")) {
  app.listen(PORT, () => {
    console.log(`[osv-mcp] Listening on http://localhost:${PORT}/mcp`);
  });
}
