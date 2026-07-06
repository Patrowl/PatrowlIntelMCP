# patrowl-intel-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes **PatrowlIntel**
vulnerability intelligence (CVEs, EPSS, CISA KEV, public exploits, trending
attacks) to any MCP client. It is a thin, read-only stdio wrapper over the
public PatrowlIntel API.

> **v0** — three tools: `search_cves`, `get_cve`, `list_trending_attacks`.

## Tools

| Tool | Purpose |
|---|---|
| `search_cves` | Filter/rank the CVE feed (risk score, EPSS, KEV, exploited, technology, dates). |
| `get_cve` | Full record for one CVE (CVSS, EPSS, KEV, SSVC, exploits, references). |
| `list_trending_attacks` | Recent trending threats, filterable by severity and date. |

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `PATROWL_INTEL_API_BASE` | `http://localhost:8686` | Backend API base URL. |
| `PATROWL_INTEL_WEB_BASE` | = API base | Public site base used for CVE citation links. |
| `PATROWL_INTEL_API_KEY` | _(unset)_ | Reserved for the future authenticated tier. |
| `PATROWL_INTEL_TIMEOUT` | `15` | Per-request timeout (seconds). |

## Run

```bash
# from the repo root
uv run patrowl-intel-mcp          # or: pip install -e . && patrowl-intel-mcp
```

## Client config

```jsonc
{
  "mcpServers": {
    "patrowl-intel": {
      "command": "uvx",
      "args": ["patrowl-intel-mcp"],
      "env": { "PATROWL_INTEL_API_BASE": "https://<your-intel-host>" }
    }
  }
}
```

During local development, point `command` at your checkout instead:

```jsonc
{ "command": "uv", "args": ["--directory", "/path/to/PatrowlIntelMCP", "run", "patrowl-intel-mcp"] }
```
