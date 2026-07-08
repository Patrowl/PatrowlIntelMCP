"""PatrowlIntel MCP server.

Thin, read-only wrapper over the public PatrowlIntel API exposing four tools:
`search_cves`, `get_cve`, `classify_ssvc`, and `list_trending_attacks`.
`classify_ssvc` adds deterministic SSVC classification and remediation-SLA
planning on top of the CVE feed. Configure the backend with
PATROWL_INTEL_API_BASE (default https://intel.patrowl.io).

Transport defaults to stdio (for local `uvx` use). Set
PATROWL_INTEL_MCP_TRANSPORT=streamable-http (with PATROWL_INTEL_MCP_HOST /
PATROWL_INTEL_MCP_PORT) to run it as a networked service, e.g. in Docker.
"""
import os
from datetime import date, timedelta
from typing import Annotated, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from . import ssvc
from .client import PatrowlIntelClient, PatrowlIntelError

mcp = FastMCP(
    "patrowl-intel",
    host=os.getenv("PATROWL_INTEL_MCP_HOST", "127.0.0.1"),
    port=int(os.getenv("PATROWL_INTEL_MCP_PORT", "8790")),
)
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


class SsvcAsset(BaseModel):
    """One CVE-on-an-asset to classify. The CVE-derived decision points
    (exploitation, automatable, tech_impact, is_kev) are auto-populated from
    PatrowlIntel; the asset-specific points (publicly_exposed,
    mission_wellbeing) come from you. Any point can be overridden explicitly."""
    cve_id: Annotated[str, Field(description="CVE identifier, e.g. 'CVE-2024-3400'.")]
    asset: Annotated[Optional[str], Field(description="Free-text asset/host label, echoed back in the result.")] = None
    publicly_exposed: Annotated[bool, Field(description="Is the asset reachable by unauthenticated entities over a public network? (BOD 26-04 input)")] = True
    mission_wellbeing: Annotated[Literal["low", "medium", "high"], Field(description="Impact on mission-essential functions / public well-being. (CISA Coordinator input)")] = "high"
    exploitation: Annotated[Optional[Literal["none", "poc", "active"]], Field(description="Override the CVE-derived exploitation status.")] = None
    automatable: Annotated[Optional[Literal["no", "yes"]], Field(description="Override the CVE-derived automatability.")] = None
    tech_impact: Annotated[Optional[Literal["partial", "total"]], Field(description="Override the CVE-derived technical impact.")] = None


def _norm_scored(cve_ssvc: dict) -> dict:
    """Normalise the CVE's stored SSVC block to clean enum strings."""
    auto = cve_ssvc.get("automatable")
    auto = "yes" if auto in (True, "yes") else "no"
    ti = "total" if str(cve_ssvc.get("tech_impact")).lower() == "total" else "partial"
    exp = str(cve_ssvc.get("exploitation") or "none").lower()
    exp = exp if exp in ("none", "poc", "active") else "none"
    return {"exploitation": exp, "automatable": auto, "tech_impact": ti}


def _resolve_ssvc_inputs(c: dict, item: SsvcAsset) -> dict:
    """Resolve the six SSVC decision points for one CVE+asset, tracking the
    source and human-readable evidence behind each so the outcome is auditable.

    Each entry is {value, source, evidence}. `source` is one of:
      cve         - hard fact from the CVE record (is_kev)
      cisa_scored - value CISA published in its SSVC decision (timestamped)
      inferred    - derived from CVE evidence (KEV / public exploits)
      assumed     - unknown; backend default used, worth confirming
      caller      - supplied in the asset context
    """
    cve_ssvc = c.get("cisa_ssvc") or {}
    scored = bool(cve_ssvc.get("timestamp"))
    norm = _norm_scored(cve_ssvc)
    is_kev = bool(c.get("is_kev"))
    exploit_count = len(c.get("exploits") or [])

    # is_kev — hard fact.
    kev_added = c.get("cisa_kev_date_added")
    inputs = {"is_kev": {
        "value": is_kev, "source": "cve",
        "evidence": (f"In the CISA KEV catalog (added {kev_added})." if is_kev
                     else "Not in the CISA KEV catalog."),
    }}

    # exploitation — caller > CISA-scored > inferred from KEV/exploits.
    if item.exploitation is not None:
        inputs["exploitation"] = {"value": item.exploitation, "source": "caller",
                                  "evidence": "Overridden in the request."}
    elif scored:
        inputs["exploitation"] = {"value": norm["exploitation"], "source": "cisa_scored",
                                  "evidence": f"CISA SSVC scored {cve_ssvc.get('timestamp')}."}
    elif is_kev:
        inputs["exploitation"] = {"value": "active", "source": "inferred",
                                  "evidence": "KEV listing implies active exploitation in the wild."}
    elif exploit_count:
        inputs["exploitation"] = {"value": "poc", "source": "inferred",
                                  "evidence": f"{exploit_count} public exploit(s) referenced, no KEV listing → PoC."}
    else:
        inputs["exploitation"] = {"value": "none", "source": "inferred",
                                  "evidence": "No KEV listing and no public exploit referenced."}

    # automatable — caller > CISA-scored > assumed 'no'.
    if item.automatable is not None:
        inputs["automatable"] = {"value": item.automatable, "source": "caller",
                                 "evidence": "Overridden in the request."}
    elif scored:
        inputs["automatable"] = {"value": norm["automatable"], "source": "cisa_scored",
                                 "evidence": f"CISA SSVC scored {cve_ssvc.get('timestamp')}."}
    else:
        inputs["automatable"] = {"value": "no", "source": "assumed",
                                 "evidence": "Not scored by CISA; assumed 'no'. Confirm if steps 1-4 of the kill chain can be reliably automated."}

    # tech_impact — caller > CISA-scored > assumed 'partial'.
    if item.tech_impact is not None:
        inputs["tech_impact"] = {"value": item.tech_impact, "source": "caller",
                                 "evidence": "Overridden in the request."}
    elif scored:
        inputs["tech_impact"] = {"value": norm["tech_impact"], "source": "cisa_scored",
                                 "evidence": f"CISA SSVC scored {cve_ssvc.get('timestamp')}."}
    else:
        inputs["tech_impact"] = {"value": "partial", "source": "assumed",
                                 "evidence": "Not scored by CISA; assumed 'partial'. Set 'total' if exploitation yields full control of the target."}

    # asset-specific points — always from the caller.
    inputs["publicly_exposed"] = {"value": item.publicly_exposed, "source": "caller",
                                  "evidence": "Asset context supplied in the request."}
    inputs["mission_wellbeing"] = {"value": item.mission_wellbeing, "source": "caller",
                                   "evidence": "Asset context supplied in the request."}
    return inputs


def _classify_one(item: SsvcAsset, assessment: date) -> dict:
    c = client.get(f"/api/cves/{item.cve_id}/")
    ins = _resolve_ssvc_inputs(c, item)
    v = {k: ins[k]["value"] for k in ins}

    bod_code = ssvc.bod_decision(v["is_kev"], v["publicly_exposed"], v["automatable"], v["tech_impact"])
    bod_meta = ssvc.BOD_META[bod_code]
    cisa_key = ssvc.cisa_decision(v["exploitation"], v["automatable"], v["tech_impact"], v["mission_wellbeing"])
    cisa_meta = ssvc.CISA_META[cisa_key]

    sla_days = bod_meta["sla_days"]
    due_date = (assessment + timedelta(days=sla_days)).isoformat() if sla_days is not None else None
    kev_due = c.get("cisa_kev_due_date") if v["is_kev"] else None
    if sla_days is None:
        note = "No fixed deadline — remediate at the next scheduled system upgrade."
    elif kev_due:
        note = f"CISA KEV sets a binding federal deadline of {kev_due}; treat it as authoritative if earlier."
    else:
        note = f"Remediate within {sla_days} day(s) of {assessment.isoformat()}."

    return {
        "cve_id": c.get("cve_id"),
        "asset": item.asset,
        "url": f"{client.web_base}/cves/{c.get('cve_id')}",
        "inputs": ins,
        "bod": {
            "vector": ssvc.bod_vector(v["is_kev"], v["publicly_exposed"], v["automatable"], v["tech_impact"]),
            "code": bod_code,
            "outcome": bod_meta["headline"],
            "forensics_required": bod_meta["forensics"],
        },
        "cisa": {
            "vector": ssvc.cisa_vector(v["exploitation"], v["automatable"], v["tech_impact"], v["mission_wellbeing"]),
            "action": cisa_meta["action"],
            "priority": cisa_meta["priority"],
            "rationale": cisa_meta["sub"],
        },
        "sla": {
            "assessment_date": assessment.isoformat(),
            "days": sla_days,
            "due_date": due_date,
            "forensics_required": bod_meta["forensics"],
            "kev_federal_due_date": kev_due,
            "note": note,
        },
    }


@mcp.tool()
def classify_ssvc(
    items: Annotated[list[SsvcAsset], Field(description="CVE-on-asset entries to classify (1-50).", min_length=1, max_length=50)],
    assessment_date: Annotated[Optional[str], Field(description="ISO date the SLA clock starts from; defaults to today (UTC).")] = None,
) -> dict:
    """Deterministically classify one or more CVE+asset pairs with SSVC and plan
    remediation SLAs. For each entry it fetches the CVE, resolves the SSVC
    decision points (auto-populating exploitation / automatable / tech_impact /
    KEV from PatrowlIntel and taking public-exposure / mission impact from the
    asset context), then computes — from fixed lookup tables, no guessing:

      - the CISA BOD 26-04 remediation vector & timeline (e.g. KEV:Y / PE:Y /
        A:Y / T:T -> Within 3 days + forensics), and
      - the CISA Coordinator SSVC action (Track / Track* / Attend / Act).

    It also converts the BOD outcome into a concrete due_date from
    assessment_date. Every decision point carries a `source` and `evidence`
    string so you can explain the reasoning and flag `assumed` inputs (not
    scored by CISA) that the asset owner should confirm."""
    if assessment_date:
        try:
            assessment = date.fromisoformat(assessment_date)
        except ValueError:
            raise PatrowlIntelError(f"assessment_date must be an ISO date (YYYY-MM-DD), got {assessment_date!r}.")
    else:
        assessment = date.today()

    results = []
    for item in items:
        try:
            results.append(_classify_one(item, assessment))
        except PatrowlIntelError as e:
            results.append({"cve_id": item.cve_id, "asset": item.asset, "error": str(e)})
    return {"assessment_date": assessment.isoformat(), "count": len(results), "results": results}


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
    transport = os.getenv("PATROWL_INTEL_MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
