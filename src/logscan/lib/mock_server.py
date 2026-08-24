"""In-process mock Kaspersky OpenTIP server for local development.

Provides a small HTTP server that mimics the OpenTIP ``/search/ip`` and
``/search/hash`` endpoints so logscan can be run end-to-end without a real
API key (see the ``--mock`` CLI flag).

The server runs in a background thread and is intended to be started and
stopped within a single CLI invocation.
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

# API key substituted when running against the in-process mock. The mock
# accepts any key, so this value is only used to satisfy the client.
DUMMY_API_KEY = "local-mock-key"

_DEFAULT_HOST = "127.0.0.1"

# Verdicts returned by the mock, cycled deterministically per artefact.
_ZONES = ("Green", "Grey", "Yellow", "Orange", "Red")

_IP_PATH = "/search/ip"
_HASH_PATH = "/search/hash"


def _is_ip(value: str) -> bool:
    """Best-effort IP detection matching how the client dispatches lookups."""
    return "." in value or ":" in value


def _zone_for(value: str) -> str:
    """Pick a stable zone for an artefact (same value -> same verdict)."""
    digest = int(hashlib.sha1(value.encode("utf-8")).hexdigest(), 16)
    return _ZONES[digest % len(_ZONES)]


def build_response(artefact: str) -> Dict[str, Any]:
    """Build a mock OpenTIP response payload for a single artefact."""
    zone = _zone_for(artefact)

    if _is_ip(artefact):
        return {
            "Zone": zone,
            "IpGeneralInfo": {
                "Status": "known",
                "CountryCode": "US",
                "HitsCount": 1234,
                "CategoriesWithZone": [
                    {"Name": "spam", "Zone": "Red"},
                    {"Name": "botnet", "Zone": "Yellow"},
                ],
            },
        }

    detections: list[Dict[str, str]] = []
    if zone != "Green":
        detections.append({"DetectionName": f"Mock.Generic.{zone}"})
    return {
        "Zone": zone,
        "FileGeneralInfo": {
            "FileStatus": "Clean" if zone == "Green" else "Suspicious",
            "Size": 1024,
            "HitsCount": 1,
            "DetectionsInfo": detections,
        },
    }


class MockOpenTIPHandler(BaseHTTPRequestHandler):
    """Handle OpenTIP-style lookup GET requests."""

    def do_GET(self) -> None:  # noqa: N802 (stdlib method name)
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        request = (query.get("request") or [""])[0]

        if parsed.path.endswith(_IP_PATH):
            payload, status = build_response(request), 200
        elif parsed.path.endswith(_HASH_PATH):
            payload, status = build_response(request), 200
        else:
            payload, status = {"error": "Not found"}, 404

        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Keep test/dev output quiet.
        return


class MockOpenTIPServer:
    """A self-contained OpenTIP mock running in a background thread."""

    def __init__(self, host: str = _DEFAULT_HOST, port: int = 0) -> None:
        # port=0 asks the OS to pick a free ephemeral port.
        self._httpd = ThreadingHTTPServer((host, port), MockOpenTIPHandler)
        bound_host, bound_port = self._httpd.server_address
        self._url = f"http://{bound_host}:{bound_port}/api/v1/"
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            daemon=True,
            name="mock-opentip",
        )

    def start(self) -> "MockOpenTIPServer":
        """Start serving in the background and return self for chaining."""
        self._thread.start()
        return self

    @property
    def url(self) -> str:
        """Base endpoint URL in the production OpenTIP URL shape."""
        return self._url

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def stop(self) -> None:
        """Stop the server and release the bound port."""
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


__all__ = [
    "DUMMY_API_KEY",
    "MockOpenTIPHandler",
    "MockOpenTIPServer",
    "build_response",
]
