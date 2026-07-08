"""Deterministic SSVC decision logic — no network, no `ssvc` library.

Two stakeholder decision models, both pure lookups so classification is
reproducible and auditable:

  - `bod_decision`  : CISA BOD 26-04 remediation timeline (16-row table).
                      https://certcc.github.io/SSVC/howto/cisa_response/#table-of-values
  - `cisa_decision` : CISA Coordinator SSVC action, Track / Track* / Attend / Act
                      (36-row table generated from the ssvc==1.2.3 library the
                      PatrowlIntel backend uses).

These tables are transcribed from the PatrowlIntel backend (`cves/utils.py`)
and frontend (`useSsvc.ts`); `tests/test_ssvc.py` guards the transcription.
"""

# --- CISA BOD 26-04: remediation timeline -----------------------------------
# key = (is_kev, publicly_exposed, automatable == "yes", tech_impact == "total")
_BOD_TABLE = {
    (False, False, False, False): "FSU",
    (False, False, False, True):  "FSU",
    (False, False, True,  False): "60D",
    (False, False, True,  True):  "60D",
    (False, True,  False, False): "60D",
    (False, True,  False, True):  "14D",
    (False, True,  True,  False): "14D",
    (False, True,  True,  True):  "3D",
    (True,  False, False, False): "14D",
    (True,  False, False, True):  "14D",
    (True,  False, True,  False): "14D",
    (True,  False, True,  True):  "3DF",
    (True,  True,  False, False): "14D",
    (True,  True,  False, True):  "3DF",
    (True,  True,  True,  False): "3D",
    (True,  True,  True,  True):  "3DF",
}

# code -> remediation outcome. `sla_days` is None for FSU (no fixed deadline;
# fix at the next scheduled system upgrade).
BOD_META = {
    "FSU": {"headline": "At next scheduled system upgrade", "sla_days": None, "forensics": False},
    "60D": {"headline": "Within 60 days", "sla_days": 60, "forensics": False},
    "14D": {"headline": "Within 14 days", "sla_days": 14, "forensics": False},
    "3D":  {"headline": "Within 3 days", "sla_days": 3, "forensics": False},
    "3DF": {"headline": "Within 3 days + forensics", "sla_days": 3, "forensics": True},
}

# --- CISA Coordinator SSVC: Track / Track* / Attend / Act -------------------
# key = "exploitation|automatable|tech_impact|mission_wellbeing"
_CISA_TABLE = {
    "none|no|partial|low": "track", "none|no|partial|medium": "track", "none|no|partial|high": "track_star",
    "none|no|total|low": "track", "none|no|total|medium": "track", "none|no|total|high": "track_star",
    "none|yes|partial|low": "track", "none|yes|partial|medium": "track", "none|yes|partial|high": "attend",
    "none|yes|total|low": "track", "none|yes|total|medium": "track", "none|yes|total|high": "attend",
    "poc|no|partial|low": "track", "poc|no|partial|medium": "track", "poc|no|partial|high": "track_star",
    "poc|no|total|low": "track", "poc|no|total|medium": "track_star", "poc|no|total|high": "attend",
    "poc|yes|partial|low": "track", "poc|yes|partial|medium": "track", "poc|yes|partial|high": "attend",
    "poc|yes|total|low": "track", "poc|yes|total|medium": "track_star", "poc|yes|total|high": "attend",
    "active|no|partial|low": "track", "active|no|partial|medium": "track", "active|no|partial|high": "attend",
    "active|no|total|low": "track", "active|no|total|medium": "attend", "active|no|total|high": "act",
    "active|yes|partial|low": "attend", "active|yes|partial|medium": "attend", "active|yes|partial|high": "act",
    "active|yes|total|low": "attend", "active|yes|total|medium": "act", "active|yes|total|high": "act",
}

CISA_META = {
    "track":      {"action": "Track", "priority": "low", "sub": "Monitor — no action needed yet"},
    "track_star": {"action": "Track*", "priority": "medium", "sub": "Monitor closely for change"},
    "attend":     {"action": "Attend", "priority": "medium", "sub": "Engage internally / supply resources"},
    "act":        {"action": "Act", "priority": "immediate", "sub": "Act now"},
}


def _norm_yesno(value) -> str:
    v = "yes" if value is True else "no" if value is False else str(value).strip().lower()
    if v not in ("no", "yes"):
        raise ValueError(f"automatable must be 'no'/'yes', got {value!r}")
    return v


def _norm_impact(value) -> str:
    v = str(value).strip().lower()
    if v not in ("partial", "total"):
        raise ValueError(f"tech_impact must be 'partial'/'total', got {value!r}")
    return v


def _norm_exploitation(value) -> str:
    v = str(value).strip().lower()
    if v not in ("none", "poc", "active"):
        raise ValueError(f"exploitation must be 'none'/'poc'/'active', got {value!r}")
    return v


def _norm_mission(value) -> str:
    v = str(value).strip().lower()
    if v not in ("low", "medium", "high"):
        raise ValueError(f"mission_wellbeing must be 'low'/'medium'/'high', got {value!r}")
    return v


def bod_decision(is_kev=False, publicly_exposed=False, automatable="no", tech_impact="partial") -> str:
    """Map the four CISA BOD 26-04 decision points to a remediation code
    (FSU / 60D / 14D / 3D / 3DF). Tolerates bools and casing on the inputs."""
    auto = _norm_yesno(automatable)
    impact = _norm_impact(tech_impact)
    return _BOD_TABLE[(bool(is_kev), bool(publicly_exposed), auto == "yes", impact == "total")]


def cisa_decision(exploitation="none", automatable="no", tech_impact="partial", mission_wellbeing="high") -> str:
    """Map the four CISA Coordinator decision points to an action key
    (track / track_star / attend / act)."""
    key = "|".join((
        _norm_exploitation(exploitation),
        _norm_yesno(automatable),
        _norm_impact(tech_impact),
        _norm_mission(mission_wellbeing),
    ))
    return _CISA_TABLE[key]


def bod_vector(is_kev: bool, publicly_exposed: bool, automatable: str, tech_impact: str) -> str:
    """Compact BOD 26-04 vector, e.g. 'KEV:Y / PE:Y / A:Y / T:T'."""
    yn = lambda b: "Y" if b else "N"
    return (
        f"KEV:{yn(is_kev)} / PE:{yn(publicly_exposed)} / "
        f"A:{yn(_norm_yesno(automatable) == 'yes')} / "
        f"T:{'T' if _norm_impact(tech_impact) == 'total' else 'P'}"
    )


def cisa_vector(exploitation: str, automatable: str, tech_impact: str, mission_wellbeing: str) -> str:
    """Compact CISA Coordinator vector, e.g. 'E:A / A:Y / T:T / M:H'."""
    e = {"none": "N", "poc": "P", "active": "A"}[_norm_exploitation(exploitation)]
    a = "Y" if _norm_yesno(automatable) == "yes" else "N"
    t = "T" if _norm_impact(tech_impact) == "total" else "P"
    m = {"low": "L", "medium": "M", "high": "H"}[_norm_mission(mission_wellbeing)]
    return f"E:{e} / A:{a} / T:{t} / M:{m}"
