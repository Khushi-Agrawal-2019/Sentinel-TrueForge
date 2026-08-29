# OSV.dev Model Context Protocol (MCP) Server

This MCP server provides keyless, zero-cost vulnerability intelligence for SentinelPR by integrating with the public OSV.dev REST API.

## Tools Exposed

### 1. `check_vulnerabilities`
Checks a single package for known CVEs/GHSAs, severity scores, and resolution versions.
- **Parameters**:
  - `package_name` (string, required): e.g. `"jinja2"`, `"requests"`, `"express"`
  - `ecosystem` (string, optional, default `"PyPI"`): e.g. `"PyPI"`, `"npm"`, `"Maven"`, `"Go"`
  - `version` (string, optional): e.g. `"2.11.2"`

### 2. `batch_check`
Scans an entire manifest's dependencies in a single batch API call.
- **Parameters**:
  - `dependencies` (array of objects): `[{ name: "jinja2", ecosystem: "PyPI", version: "2.11.2" }]`

## Running Standalone

```bash
cd mcp-servers/osv-mcp
npm install
npm test
```

## TrueForge Integration

Connect this server to TrueForge by referencing it in your `agent.json`:
```json
{
  "mcp_servers": [
    {
      "name": "osv",
      "url": "http://localhost:8950/mcp",
      "enable_tools": ["@all"],
      "preload": true
    }
  ]
}
```
