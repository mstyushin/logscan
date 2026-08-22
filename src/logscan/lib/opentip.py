"""Kaspersky OpenTIP API client for logscan.

Performs synchronous lookups of IP addresses and file hashes against the
Kaspersky Threat Intelligence Portal (OpenTIP) API and normalizes the
responses into compact result summaries.

API reference: https://opentip.kaspersky.com/Help/Doc_data/WorkingWithAPI.htm
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests

logger = logging.getLogger(__name__)

# Default timeout for individual HTTP requests (seconds).
REQUEST_TIMEOUT = 30

# Response zones understood by the client.
RED = "Red"
ORANGE = "Orange"
YELLOW = "Yellow"
GREY = "Grey"
GREEN = "Green"


class OpenTIPError(Exception):
    """Base exception for OpenTIP API errors."""


class OpenTIPQuotaExceeded(OpenTIPError):
    """Raised when the API returns HTTP 403 (quota or request limit)."""


class OpenTIPNotFound(OpenTIPError):
    """Raised when the API returns HTTP 404 (no lookup results)."""


def is_hash(value: str) -> bool:
    """Return True if the value looks like a hash (32/40/64 hex chars)."""
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value))


def is_ip_address(value: str) -> bool:
    """Return True if the value looks like an IP address (IPv4 or IPv6)."""
    return ":" in value or "." in value


class OpenTIPClient:
    """Client for the Kaspersky OpenTIP v1 API."""

    def __init__(
        self,
        api_key: str,
        endpoint: str = "https://opentip.kaspersky.com/api/v1/",
        backoff_interval: int = 15,
        max_retries: int = 5,
    ) -> None:
        if not api_key:
            raise ValueError("OpenTIP API key is required")
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/") + "/"
        self.backoff_interval = backoff_interval
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({"x-api-key": api_key})

    def _request(
        self, path: str, params: Dict[str, str], retries: int | None = None
    ) -> Dict[str, Any]:
        """Perform a GET request, backing off on quota (403) errors."""
        url = self.endpoint + path
        retries = retries if retries is not None else self.max_retries
        last_error: OpenTIPError | None = None

        for attempt in range(retries):
            try:
                response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as exc:
                last_error = OpenTIPError(f"Network error while calling {url}: {exc}")
            else:
                # unlike virustotal which returns honest 409, opentip responds with 403
                if response.status_code == 403:
                    # Quota exceeded: record the error and fall through to the
                    # backoff/retry logic below. Do not treat the response as a
                    # successful lookup.
                    last_error = OpenTIPQuotaExceeded(
                        f"OpenTIP quota/request limit exceeded (HTTP 403) for {url}"
                    )
                elif response.status_code == 404:
                    raise OpenTIPNotFound(
                        f"No lookup results found (HTTP 404) for "
                        f"{params.get('request', '')!r}"
                    )
                elif response.status_code == 401:
                    raise OpenTIPError(
                        "OpenTIP authentication failed (HTTP 401): check your API token"
                    )
                elif response.status_code >= 400:
                    try:
                        body = response.json()
                        detail = body.get("error", body.get("message", ""))
                    except ValueError:
                        detail = response.text[:200]
                    raise OpenTIPError(
                        f"OpenTIP API error {response.status_code} for {url}: {detail}"
                    )
                else:
                    # Success (2xx/3xx): parse and return the payload.
                    try:
                        return response.json()
                    except ValueError as exc:
                        raise OpenTIPError(
                            f"Invalid JSON response from {url}: {response.text[:200]}"
                        ) from exc

            # Transient/quota error: back off and retry.
            delay = self.backoff_interval * (attempt + 1)
            logger.warning(
                "%s; retrying in %ds (attempt %d/%d)",
                last_error,
                delay,
                attempt + 1,
                retries,
            )
            if attempt < retries - 1:
                time.sleep(delay)

        assert last_error is not None
        raise last_error

    def lookup(self, artefact: str) -> Dict[str, Any]:
        """Look up a single artefact (hash or IP) on OpenTIP.

        Args:
            artefact: A hash (MD5/SHA-1/SHA-256) or an IP address.

        Returns:
            The raw JSON response from OpenTIP.

        Raises:
            ValueError: If the artefact type is unsupported.
            OpenTIPError: On API errors.
        """
        if is_hash(artefact):
            return self._request("search/hash", {"request": artefact})
        if is_ip_address(artefact):
            return self._request("search/ip", {"request": artefact})
        raise OpenTIPError(f"Unsupported artefact type: {artefact!r}")

    def analyze(self, artefacts: Dict[str, List[str]]) -> List[Dict[str, str]]:
        """Analyse a batch of artefacts.

        Args:
            artefacts: A dict with ``ips`` and ``hashes`` keys, each a list
                of strings.

        Returns:
            A normalized list of results, each with keys ``artefact``,
            ``result``, and ``date``.
        """
        results: List[Dict[str, str]] = []
        all_values: List[str] = []
        all_values.extend(artefacts.get("ips", []))
        all_values.extend(artefacts.get("hashes", []))

        for value in all_values:
            try:
                payload = self.lookup(value)
                summary = self.summarize(value, payload)
            except OpenTIPError as exc:
                logger.error("Failed to look up %s: %s", value, exc)
                summary = f"error: {exc}"
            results.append(
                {
                    "artefact": value,
                    "result": summary,
                    "date": datetime.now(timezone.utc).isoformat(),
                }
            )
        return results

    def summarize(self, artefact: str, payload: Dict[str, Any]) -> str:
        """Build a compact human-readable summary from an OpenTIP response."""
        zone = payload.get("Zone", GREY)

        if is_hash(artefact):
            info = payload.get("FileGeneralInfo") or {}
            parts = [f"zone={zone}"]
            file_status = info.get("FileStatus")
            if file_status:
                parts.append(f"status={file_status}")
            detection_name = _first_detection_name(info.get("DetectionsInfo"))
            if detection_name:
                parts.append(f"detection={detection_name}")
            size = info.get("Size")
            if size is not None:
                parts.append(f"size={size}")
            hits = info.get("HitsCount")
            if hits is not None:
                parts.append(f"hits={hits}")
            return "; ".join(parts)

        if is_ip_address(artefact):
            info = payload.get("IpGeneralInfo") or {}
            parts = [f"zone={zone}"]
            status = info.get("Status")
            if status:
                parts.append(f"status={status}")
            country = info.get("CountryCode")
            if country:
                parts.append(f"country={country}")
            categories = _format_categories(info.get("CategoriesWithZone"))
            if categories:
                parts.append(f"categories={categories}")
            hits = info.get("HitsCount")
            if hits is not None:
                parts.append(f"hits={hits}")
            return "; ".join(parts)

        return f"zone={zone}"


def _first_detection_name(detections_info: Any) -> str | None:
    """Return the first detection name from ``DetectionsInfo``."""
    if not isinstance(detections_info, list):
        return None
    for entry in detections_info:
        if isinstance(entry, dict):
            name = entry.get("DetectionName")
            if name:
                return str(name)
    return None


def _format_categories(categories_with_zone: Any) -> str:
    """Format category names with their zones, e.g. 'spam[Red], botnet[Yellow]'."""
    if not isinstance(categories_with_zone, list):
        return ""
    formatted: List[str] = []
    for entry in categories_with_zone:
        if isinstance(entry, dict):
            name = entry.get("Name")
            zone = entry.get("Zone")
            if name:
                formatted.append(f"{name}[{zone}]")
    return ", ".join(formatted)
