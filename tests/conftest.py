"""Shared pytest fixtures for the logscan test suite."""

from __future__ import annotations

from typing import Any, Dict, List
from types import SimpleNamespace

import pytest

from logscan.lib.config import Settings

# All environment variables that logscan reads; cleared for test isolation.
LOGSCAN_ENV_VARS = [
    "OPENTIP_API_KEY",
    "TELEGRAM_TOKEN",
    "TELEGRAM_ALLOWED_CHATS",
    "OPENTIP_ENDPOINT",
    "LOGSCAN_REPORT_FORMAT",
    "LOGSCAN_REPORT_DIR",
    "OPENTIP_BACKOFF_INTERVAL",
    "OPENTIP_MAX_RETRIES",
    "LOGSCAN_INCLUDE_PRIVATE_IPS",
]


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear every logscan env var before a test runs."""
    for name in LOGSCAN_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def sample_ip_payload() -> Dict[str, Any]:
    """A representative OpenTIP /search/ip response."""
    return {
        "Zone": "Red",
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


@pytest.fixture
def sample_hash_payload() -> Dict[str, Any]:
    """A representative OpenTIP /search/hash response."""
    return {
        "Zone": "Green",
        "FileGeneralInfo": {
            "FileStatus": "Clean",
            "Size": 1024,
            "HitsCount": 1,
            "DetectionsInfo": [
                {"DetectionName": "Trojan.GenericKD.123"},
                {"DetectionName": "Another.Detection"},
            ],
        },
    }


@pytest.fixture
def minimal_settings() -> Settings:
    """A Settings instance with analysis configured but no Telegram token."""
    return Settings(
        opentip_api_key="test-api-key",
        opentip_endpoint="https://opentip.example.com/api/v1/",
    )


@pytest.fixture
def cli_args() -> SimpleNamespace:
    """A SimpleNamespace mimicking the parsed argparse namespace."""
    return SimpleNamespace(
        service=False,
        file=None,
        api_key=None,
        endpoint=None,
        format=None,
        report_dir=None,
        include_private_ips=False,
        verbose=False,
    )


@pytest.fixture
def sample_results() -> List[Dict[str, str]]:
    """A list of normalized analysis records for report tests."""
    return [
        {
            "artefact": "8.8.8.8",
            "result": "zone=Green; status=Good",
            "date": "2026-01-01T00:00:00+00:00",
        },
        {
            "artefact": "abc123",
            "result": "zone=Red; status=Malware",
            "date": "2026-01-01T00:01:00+00:00",
        },
    ]


@pytest.fixture
def report_dir(tmp_path) -> str:
    """Return a fresh temporary directory for report output."""
    path = tmp_path / "reports"
    path.mkdir()
    return str(path)
