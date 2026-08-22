from __future__ import annotations


import pytest
import responses
from requests.exceptions import ConnectionError

from logscan.lib.opentip import (
    GREY,
    OpenTIPClient,
    OpenTIPError,
    OpenTIPNotFound,
    OpenTIPQuotaExceeded,
    _first_detection_name,
    _format_categories,
    is_hash,
    is_ip_address,
)

ENDPOINT = "https://opentip.example.com/api/v1/"
BASE_URL = ENDPOINT.rstrip("/") + "/"
IP_URL = BASE_URL + "search/ip"
HASH_URL = BASE_URL + "search/hash"


def make_client(**kwargs) -> OpenTIPClient:
    return OpenTIPClient(
        api_key="test-key",
        endpoint=ENDPOINT,
        backoff_interval=kwargs.pop("backoff_interval", 0),
        max_retries=kwargs.pop("max_retries", 3),
        **kwargs,
    )


class TestPredicates:
    @pytest.mark.parametrize(
        "value",
        ["a" * 32, "b" * 40, "c" * 64, "ABCDEF0123456789ABCDEF0123456789"],
    )
    def test_is_hash_true(self, value: str) -> None:
        assert is_hash(value) is True

    @pytest.mark.parametrize(
        "value",
        ["8.8.8.8", "abc", "z" * 33, "a" * 65, ""],
    )
    def test_is_hash_false(self, value: str) -> None:
        assert is_hash(value) is False

    @pytest.mark.parametrize("value", ["8.8.8.8", "2001:db8::1", "1.2.3"])
    def test_is_ip_address_true(self, value: str) -> None:
        assert is_ip_address(value) is True

    @pytest.mark.parametrize("value", ["abc", "a" * 32, ""])
    def test_is_ip_address_false(self, value: str) -> None:
        assert is_ip_address(value) is False


class TestInit:
    def test_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="API key is required"):
            OpenTIPClient(api_key="")

    def test_normalizes_endpoint_trailing_slash(self) -> None:
        client = OpenTIPClient(api_key="k", endpoint="https://host/base")
        assert client.endpoint == "https://host/base/"


class TestLookup:
    @responses.activate
    def test_hash_lookup_hits_hash_endpoint(self, sample_hash_payload) -> None:
        responses.add(
            responses.GET,
            HASH_URL,
            json=sample_hash_payload,
            status=200,
        )
        client = make_client()
        result = client.lookup("a" * 32)
        assert result == sample_hash_payload
        assert responses.calls[0].request.url.startswith(HASH_URL)

    @responses.activate
    def test_ip_lookup_hits_ip_endpoint(self, sample_ip_payload) -> None:
        responses.add(responses.GET, IP_URL, json=sample_ip_payload, status=200)
        client = make_client()
        result = client.lookup("8.8.8.8")
        assert result == sample_ip_payload
        assert responses.calls[0].request.url.startswith(IP_URL)

    @responses.activate
    def test_lookup_unsupported_artefact(self) -> None:
        client = make_client()
        with pytest.raises(OpenTIPError, match="Unsupported artefact type"):
            client.lookup("not-an-artefact")


class TestRequestErrors:
    @responses.activate
    def test_404_raises_not_found(self) -> None:
        responses.add(responses.GET, IP_URL, status=404)
        client = make_client()
        with pytest.raises(OpenTIPNotFound):
            client.lookup("8.8.8.8")

    @responses.activate
    def test_401_raises_auth_error(self) -> None:
        responses.add(responses.GET, IP_URL, status=401)
        client = make_client()
        with pytest.raises(OpenTIPError, match="authentication failed"):
            client.lookup("8.8.8.8")

    @responses.activate
    def test_400_raises_api_error_with_detail(self) -> None:
        responses.add(
            responses.GET,
            IP_URL,
            status=400,
            json={"error": "Bad request"},
        )
        client = make_client()
        with pytest.raises(OpenTIPError, match="Bad request"):
            client.lookup("8.8.8.8")

    @responses.activate
    def test_invalid_json_raises(self) -> None:
        responses.add(responses.GET, IP_URL, body="not json", status=200)
        client = make_client()
        with pytest.raises(OpenTIPError, match="Invalid JSON"):
            client.lookup("8.8.8.8")

    @responses.activate
    def test_network_error_retries_then_raises(self, monkeypatch) -> None:
        responses.add(responses.GET, IP_URL, body=ConnectionError("boom"))
        sleeps: list[float] = []
        monkeypatch.setattr("logscan.lib.opentip.time.sleep", sleeps.append)
        client = make_client(max_retries=3)
        with pytest.raises(OpenTIPError, match="Network error"):
            client.lookup("8.8.8.8")
        # One delay per retry attempt (attempts 0 and 1), not the final one.
        assert len(sleeps) == 2


class TestBackoff:
    @responses.activate
    def test_403_retries_and_succeeds(self, monkeypatch, sample_ip_payload) -> None:
        responses.add(responses.GET, IP_URL, status=403, json={"error": "quota"})
        responses.add(responses.GET, IP_URL, json=sample_ip_payload, status=200)
        sleeps: list[float] = []
        monkeypatch.setattr("logscan.lib.opentip.time.sleep", sleeps.append)
        client = make_client(backoff_interval=5, max_retries=3)
        result = client.lookup("8.8.8.8")
        assert result == sample_ip_payload
        assert sleeps == [5]  # backoff_interval * (attempt+1)

    @responses.activate
    def test_403_exhausted_raises(self, monkeypatch) -> None:
        responses.add(responses.GET, IP_URL, status=403, json={"error": "quota"})
        sleeps: list[float] = []
        monkeypatch.setattr("logscan.lib.opentip.time.sleep", sleeps.append)
        client = make_client(backoff_interval=2, max_retries=3)
        with pytest.raises(OpenTIPQuotaExceeded):
            client.lookup("8.8.8.8")
        assert sleeps == [2, 4]


class TestSummarize:
    def test_hash_summary(self, sample_hash_payload) -> None:
        client = make_client()
        summary = client.summarize("a" * 32, sample_hash_payload)
        assert "zone=Green" in summary
        assert "status=Clean" in summary
        assert "size=1024" in summary
        assert "hits=1" in summary
        assert "detection=Trojan.GenericKD.123" in summary

    def test_hash_without_file_info_defaults_grey(self) -> None:
        client = make_client()
        summary = client.summarize("a" * 32, {})
        assert summary == f"zone={GREY}"

    def test_ip_summary(self, sample_ip_payload) -> None:
        client = make_client()
        summary = client.summarize("8.8.8.8", sample_ip_payload)
        assert "zone=Red" in summary
        assert "status=known" in summary
        assert "country=US" in summary
        assert "categories=spam[Red], botnet[Yellow]" in summary
        assert "hits=1234" in summary

    def test_ip_without_info_defaults_grey(self) -> None:
        client = make_client()
        assert client.summarize("8.8.8.8", {}) == f"zone={GREY}"

    def test_unknown_type_returns_zone_only(self) -> None:
        client = make_client()
        assert client.summarize("something", {"Zone": "Orange"}) == "zone=Orange"


class TestAnalyze:
    @responses.activate
    def test_analyze_batch(self, sample_ip_payload, sample_hash_payload) -> None:
        responses.add(responses.GET, IP_URL, json=sample_ip_payload, status=200)
        responses.add(responses.GET, HASH_URL, json=sample_hash_payload, status=200)
        client = make_client()
        results = client.analyze({"ips": ["8.8.8.8"], "hashes": ["a" * 32]})
        assert len(results) == 2
        assert results[0]["artefact"] == "8.8.8.8"
        assert results[1]["artefact"] == "a" * 32
        for record in results:
            assert set(record.keys()) == {"artefact", "result", "date"}
            assert record["date"]

    @responses.activate
    def test_analyze_records_error_per_item(self) -> None:
        responses.add(responses.GET, IP_URL, status=500, json={"error": "boom"})
        client = make_client()
        results = client.analyze({"ips": ["8.8.8.8"], "hashes": []})
        assert len(results) == 1
        assert results[0]["artefact"] == "8.8.8.8"
        assert results[0]["result"].startswith("error:")


class TestHelpers:
    def test_first_detection_name(self) -> None:
        detections = [{"DetectionName": "First"}, {"DetectionName": "Second"}]
        assert _first_detection_name(detections) == "First"

    def test_first_detection_name_empty_entries(self) -> None:
        assert _first_detection_name([{"Other": 1}, {"DetectionName": "X"}]) == "X"

    def test_first_detection_name_none(self) -> None:
        assert _first_detection_name(None) is None
        assert _first_detection_name("not-a-list") is None

    def test_format_categories(self) -> None:
        cats = [
            {"Name": "spam", "Zone": "Red"},
            {"Name": "botnet", "Zone": "Yellow"},
            {"Other": "x"},
        ]
        assert _format_categories(cats) == "spam[Red], botnet[Yellow]"

    def test_format_categories_empty(self) -> None:
        assert _format_categories(None) == ""
        assert _format_categories("nope") == ""
