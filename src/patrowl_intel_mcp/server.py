"""PatrowlIntel MCP server (v0).

stdio transport, thin HTTP over the public read-only API. Exposes three tools:
`search_cves`, `get_cve`, and `list_trending_attacks`. Configure the backend
with PATROWL_INTEL_API_BASE (default https://intel.patrowl.io).
"""
from typing import Annotated, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .client import PatrowlIntelClient, PatrowlIntelError

mcp = FastMCP("patrowl-intel")
client = PatrowlIntelClient()

SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Ordering values accepted by the CVE `sorted_by` filter.
CVE_SORTS = {
    "cve_id", "-cve_id", "score", "-score", "published", "-published",
    "epss_score", "-epss_score", "epss_percentile", "-epss_percentile",
    "is_kev", "-is_kev",
}


def _compact_cve(c: dict) -> dict:
    """Token-efficient projection of a CVE for list results."""
    return {
        "cve_id": c.get("cve_id"),
        "summary": (c.get("summary") or "")[:280],
        "score": c.get("score"),
        "epss_score": c.get("epss_score"),
        "is_kev": c.get("is_kev"),
        "is_remote": c.get("is_remote"),
        "exploit_count": len(c.get("exploits") or []),
        "technologies": (c.get("technologies") or [])[:5],
        "url": f"{client.web_base}/cves/{c.get('cve_id')}",
    }


def _cvss_summary(cvss_data: dict) -> Optional[dict]:
    """Pick the highest CVSS version present as the headline score."""
    best = None
    for key, entry in cvss_data.items():
        if not isinstance(entry, dict) or entry.get("baseScore") is None:
            continue
        version = str(entry.get("version") or key)
        if best is None or version > best["version"]:
            best = {
                "version": version,
                "base_score": entry.get("baseScore"),
                "vector": entry.get("vectorString"),
            }
    return best


@mcp.tool()
def search_cves(
    query: Annotated[Optional[str], Field(description="Free-text match on CVE id or summary.")] = None,
    technology: Annotated[Optional[str], Field(description="Vendor/product substring, e.g. 'Apache' or 'Fortinet FortiOS'.")] = None,
    is_kev: Annotated[Optional[bool], Field(description="Only CVEs in the CISA KEV catalog.")] = None,
    has_exploit: Annotated[Optional[bool], Field(description="Only CVEs with at least one public exploit.")] = None,
    is_remote: Annotated[Optional[bool], Field(description="Only remotely exploitable CVEs.")] = None,
    min_score: Annotated[Optional[float], Field(ge=0, le=1, description="Minimum Patrowl EASM risk score (0-1).")] = None,
    min_epss: Annotated[Optional[float], Field(ge=0, le=1, description="Minimum EPSS exploit probability (0-1).")] = None,
    published_from: Annotated[Optional[str], Field(description="ISO date lower bound on publication, e.g. 2026-01-01.")] = None,
    published_to: Annotated[Optional[str], Field(description="ISO date upper bound on publication.")] = None,
    sort: Annotated[str, Field(description="Ordering; default '-score' (most risky first).")] = "-score",
    limit: Annotated[int, Field(ge=1, le=100, description="Max results, 1-100.")] = 25,
) -> dict:
    """Search the PatrowlIntel CVE feed with rich filters and return compact,
    ranked results. Use it to triage by risk (min_score / min_epss), surface
    KEV or exploited CVEs, or scope a vendor/technology. For the full record of
    one CVE, follow up with get_cve."""
    if sort not in CVE_SORTS:
        raise PatrowlIntelError(f"Invalid sort '{sort}'. Allowed: {', '.join(sorted(CVE_SORTS))}.")
    params = {
        "search": query,
        "technology": technology,
        "is_kev": is_kev,
        "has_exploit": has_exploit,
        "is_remote": is_remote,
        "score__gte": min_score,
        "epss_score__gte": min_epss,
        "published__gte": published_from,
        "published__lte": published_to,
        "sorted_by": sort,
        "page_size": limit,
    }
    data = client.get("/api/cves/", params)
    results = [_compact_cve(c) for c in data.get("results", [])]
    return {
        "count": data.get("count", 0),
        "returned": len(results),
        "has_more": bool(data.get("next")),
        "results": results,
    }


@mcp.tool()
def get_cve(
    cve_id: Annotated[str, Field(description="CVE identifier, e.g. 'CVE-2024-3400'.")],
    verbose: Annotated[bool, Field(description="Include full CVSS vectors, CPEs, all references and the raw SSVC block.")] = False,
) -> dict:
    """Fetch full intelligence for a single CVE: CVSS, EPSS, CISA KEV status and
    dates, CISA SSVC decision, public exploit links, affected technologies,
    weaknesses and references."""
    c = client.get(f"/api/cves/{cve_id}/")
    ssvc = c.get("cisa_ssvc") or {}
    out = {
        "cve_id": c.get("cve_id"),
        "summary": c.get("summary"),
        "published": c.get("published"),
        "score": c.get("score"),
        "epss_score": c.get("epss_score"),
        "epss_percentile": c.get("epss_percentile"),
        "is_kev": c.get("is_kev"),
        "cisa_kev_date_added": c.get("cisa_kev_date_added"),
        "cisa_kev_due_date": c.get("cisa_kev_due_date"),
        "is_remote": c.get("is_remote"),
        "cwes": c.get("cwes"),
        "technologies": c.get("technologies"),
        "cvss": _cvss_summary(c.get("cvss_data") or {}),
        # SSVC defaults are meaningless until CISA actually scored it (timestamp set).
        "ssvc_decision": (ssvc.get("cisa_decision") or {}).get("decision") if ssvc.get("timestamp") else None,
        "exploits": [e.get("link") for e in (c.get("exploits") or [])],
        "references": (c.get("references") or [])[:10],
        "url": f"{client.web_base}/cves/{c.get('cve_id')}",
    }
    if verbose:
        out["cvss_data"] = c.get("cvss_data")
        out["cpes"] = c.get("cpes")
        out["references"] = c.get("references")
        out["cisa_ssvc"] = ssvc
    return out


@mcp.tool()
def list_trending_attacks(
    since: Annotated[Optional[str], Field(description="ISO date lower bound on publish date, e.g. 2026-06-01.")] = None,
    min_severity: Annotated[Optional[int], Field(ge=0, le=4, description="Minimum severity: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical.")] = None,
    limit: Annotated[int, Field(ge=1, le=100, description="Max results, 1-100.")] = 25,
) -> dict:
    """List trending attacks / actively-discussed threats from the Patrowl feed,
    most recent first. Use min_severity=3 to focus on High and Critical."""
    params = {
        "published_at__gte": since,
        "severity__gte": min_severity,
        "sorted_by": "-published_at",
        "page_size": limit,
    }
    data = client.get("/api/trending_attacks/", params)
    results = [
        {
            "id": t.get("id"),
            "title": t.get("title"),
            "summary": (t.get("summary") or "")[:280],
            "severity": t.get("severity"),
            "severity_label": SEVERITY_LABELS.get(t.get("severity"), "Unknown"),
            "vendor": t.get("vendor"),
            "products": t.get("products"),
            "published_at": t.get("published_at"),
        }
        for t in data.get("results", [])
    ]
    return {
        "count": data.get("count", 0),
        "returned": len(results),
        "has_more": bool(data.get("next")),
        "results": results,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
