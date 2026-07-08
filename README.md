# patrowl-intel-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes **PatrowlIntel** vulnerability intelligence (CVEs, EPSS, CISA KEV, public exploits, trending attacks) to any MCP client. It is a thin, read-only stdio wrapper over the public PatrowlIntel API.

> **v0** — four tools: `search_cves`, `get_cve`, `classify_ssvc`, `list_trending_attacks`.

## Tools

| Tool | Purpose |
|---|---|
| `search_cves` | Filter/rank the CVE feed (risk score, EPSS, KEV, exploited, technology, dates). |
| `get_cve` | Full record for one CVE (CVSS, EPSS, KEV, SSVC, exploits, references). |
| `classify_ssvc` | Batch-classify CVE+asset pairs with SSVC and plan remediation SLAs (see below). |
| `list_trending_attacks` | Recent trending threats, filterable by severity and date. |

### `classify_ssvc`

Deterministic SSVC classification for one or more **CVE-on-an-asset** pairs, from
fixed lookup tables (no model guessing). For each entry it fetches the CVE, then:

- auto-populates the CVE-derived decision points — `exploitation`, `automatable`,
  `tech_impact`, `is_kev` — preferring CISA-scored values and falling back to
  evidence-based inference (KEV / public exploits);
- takes the asset-specific points — `publicly_exposed`, `mission_wellbeing` —
  from the request (any point can be overridden explicitly);
- computes the **CISA BOD 26-04** remediation vector & timeline
  (e.g. `KEV:Y / PE:Y / A:Y / T:T` → *Within 3 days + forensics*) and the
  **CISA Coordinator** SSVC action (*Track / Track\* / Attend / Act*);
- converts the BOD outcome into a concrete `due_date` from `assessment_date`, and
  surfaces the binding CISA KEV federal deadline when the CVE is in the catalog.

Every decision point carries a `source` (`cve` · `cisa_scored` · `inferred` ·
`assumed` · `caller`) and an `evidence` string, so the outcome is auditable and
`assumed` inputs (not scored by CISA) can be flagged for the asset owner to
confirm. The models mirror the calculator at
[intel.patrowl.io/ssvc](https://intel.patrowl.io/ssvc).

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `PATROWL_INTEL_API_BASE` | `https://intel.patrowl.io` | Backend API base URL. |
| `PATROWL_INTEL_WEB_BASE` | = API base | Public site base used for CVE citation links. |
| `PATROWL_INTEL_API_KEY` | _(unset)_ | Reserved for the future authenticated tier. |
| `PATROWL_INTEL_TIMEOUT` | `15` | Per-request timeout (seconds). |
| `PATROWL_INTEL_MCP_TRANSPORT` | `stdio` | `stdio` (local clients) or `streamable-http` (networked service). |
| `PATROWL_INTEL_MCP_HOST` | `127.0.0.1` | Bind host for `streamable-http`. |
| `PATROWL_INTEL_MCP_PORT` | `8790` | Bind port for `streamable-http`. |

## Run

```bash
# stdio (default) — for local MCP clients that launch the process
uv run patrowl-intel-mcp          # or: pip install -e . && patrowl-intel-mcp

# streamable-http — as a networked service (e.g. Docker); serves at /mcp
PATROWL_INTEL_MCP_TRANSPORT=streamable-http PATROWL_INTEL_MCP_HOST=0.0.0.0 \
  uv run patrowl-intel-mcp
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
