"""Thin HTTP client over the read-only PatrowlIntel API.

Handles config from the environment, retries on the 100/min anon throttle,
and maps upstream failures to a single clear error type so tools never leak
raw HTML or tracebacks to the model.
"""
import os
import time

import httpx

from . import __version__

DEFAULT_API_BASE = "https://intel.patrowl.io"
DEFAULT_TIMEOUT = 15.0
MAX_RETRIES = 3


class PatrowlIntelError(RuntimeError):
    """Any failure reaching or reading the PatrowlIntel API."""


class PatrowlIntelClient:
    def __init__(self, base_url=None, api_key=None, timeout=None):
        self.base_url = (base_url or os.getenv("PATROWL_INTEL_API_BASE", DEFAULT_API_BASE)).rstrip("/")
        # Public web base for citation links (the human-facing CVE pages). Falls
        # back to the API base when unset.
        self.web_base = os.getenv("PATROWL_INTEL_WEB_BASE", self.base_url).rstrip("/")
        self.api_key = api_key or os.getenv("PATROWL_INTEL_API_KEY")
        self.timeout = timeout or float(os.getenv("PATROWL_INTEL_TIMEOUT", str(DEFAULT_TIMEOUT)))

        # Distinctive User-Agent so the backend can identify and segment
        # MCP-originated traffic for usage analytics.
        headers = {
            "Accept": "application/json",
            "User-Agent": f"patrowl-intel-mcp/{__version__}",
        }
        if self.api_key:
            # DRF TokenAuthentication convention — harmless while the API is
            # still anonymous; ready for the future authenticated tier.
            headers["Authorization"] = f"Token {self.api_key}"
        self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=self.timeout)

    def get(self, path, params=None):
        params = {k: v for k, v in (params or {}).items() if v is not None}
        for attempt in range(MAX_RETRIES):
            try:
                resp = self._client.get(path, params=params)
            except httpx.RequestError as e:
                raise PatrowlIntelError(
                    f"Could not reach the PatrowlIntel API at {self.base_url}: {e}"
                ) from e

            if resp.status_code == 429:
                if attempt < MAX_RETRIES - 1:
                    retry_after = _retry_after_seconds(resp)
                    time.sleep(min(retry_after, 10))
                    continue
                raise PatrowlIntelError(
                    "PatrowlIntel API rate limit reached (100/min). Try again in a minute."
                )
            if resp.status_code == 404:
                raise PatrowlIntelError("Not found.")
            if resp.status_code >= 400:
                raise PatrowlIntelError(
                    f"PatrowlIntel API returned HTTP {resp.status_code}."
                )
            return resp.json()


def _retry_after_seconds(resp):
    try:
        return float(resp.headers.get("Retry-After", "2"))
    except ValueError:
        return 2.0
