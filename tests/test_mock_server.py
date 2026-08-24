"""Tests for logscan.lib.mock_server and its integration with OpenTIPClient."""

from __future__ import annotations


from logscan.lib.mock_server import DUMMY_API_KEY, MockOpenTIPServer, build_response
from logscan.lib.opentip import OpenTIPClient


class TestBuildResponse:
    def test_ip_payload(self) -> None:
        payload = build_response("8.8.8.8")
        assert "Zone" in payload
        assert "IpGeneralInfo" in payload
        assert "FileGeneralInfo" not in payload

    def test_hash_payload(self) -> None:
        payload = build_response("a" * 32)
        assert "Zone" in payload
        assert "FileGeneralInfo" in payload
        assert "IpGeneralInfo" not in payload

    def test_deterministic_per_artefact(self) -> None:
        assert build_response("1.2.3.4") == build_response("1.2.3.4")

    def test_varied_across_artefacts(self) -> None:
        zones = {build_response(v)["Zone"] for v in ("1.1.1.1", "2.2.2.2", "3.3.3.3")}
        assert len(zones) > 1


class TestServerLifecycle:
    def test_start_stop_releases_port(self) -> None:
        server = MockOpenTIPServer()
        server.start()
        assert server.port > 0
        assert server.url.startswith("http://127.0.0.1:")
        server.stop()

    def test_url_matches_production_shape(self) -> None:
        server = MockOpenTIPServer().start()
        try:
            assert server.url.endswith("/api/v1/")
        finally:
            server.stop()


class TestEndToEnd:
    def test_ip_and_hash_lookup_with_real_client(self) -> None:
        server = MockOpenTIPServer().start()
        try:
            client = OpenTIPClient(
                api_key=DUMMY_API_KEY,
                endpoint=server.url,
                backoff_interval=0,
                max_retries=1,
            )
            ip_payload = client.lookup("8.8.8.8")
            hash_payload = client.lookup("a" * 32)

            assert "IpGeneralInfo" in ip_payload
            assert "FileGeneralInfo" in hash_payload

            ip_summary = client.summarize("8.8.8.8", ip_payload)
            hash_summary = client.summarize("a" * 32, hash_payload)
            assert ip_summary.startswith("zone=")
            assert hash_summary.startswith("zone=")
        finally:
            server.stop()

    def test_analyze_batch_without_errors(self) -> None:
        server = MockOpenTIPServer().start()
        try:
            client = OpenTIPClient(
                api_key=DUMMY_API_KEY,
                endpoint=server.url,
                backoff_interval=0,
                max_retries=1,
            )
            results = client.analyze({"ips": ["8.8.8.8"], "hashes": ["a" * 32]})
            assert len(results) == 2
            assert all(r["result"].startswith("zone=") for r in results)
            assert not any(r["result"].startswith("error:") for r in results)
        finally:
            server.stop()
