from __future__ import annotations


import pytest
from types import SimpleNamespace

import logscan
from logscan import build_parser, main, run_cli, run_service


@pytest.fixture
def sample_log(tmp_path) -> str:
    """Create a temporary log file with IPs and hashes."""
    path = tmp_path / "access.log"
    path.write_text("conn 8.8.8.8\nmd5=5d41402abc4b2a76b9719d911017c592\n192.168.1.1\n")
    return str(path)


class FakeOpenTIPClient:
    """Replaces OpenTIPClient without touching the network."""

    def __init__(self, *args, **kwargs) -> None:
        self.results = [
            {
                "artefact": "8.8.8.8",
                "result": "zone=Green",
                "date": "2026-01-01T00:00:00+00:00",
            },
            {
                "artefact": "5d41402abc4b2a76b9719d911017c592",
                "result": "zone=Red",
                "date": "2026-01-01T00:00:00+00:00",
            },
        ]

    def analyze(self, artefacts) -> list:
        return self.results


class TestBuildParser:
    def test_parses_flags(self) -> None:
        args = build_parser().parse_args(
            ["--file", "x.log", "--api-key", "k", "--format", "json"]
        )
        assert args.file == "x.log"
        assert args.api_key == "k"
        assert args.format == "json"

    def test_service_flag(self) -> None:
        args = build_parser().parse_args(["--service"])
        assert args.service is True


class TestRunCli:
    def test_missing_api_key_returns_error(self, clean_env, capsys, sample_log) -> None:
        args = SimpleNamespace(
            api_key=None,
            endpoint=None,
            format=None,
            report_dir=None,
            include_private_ips=False,
            file=sample_log,
        )
        assert run_cli(args) == 2
        captured = capsys.readouterr()
        assert "analysis is not configured" in captured.err.lower()

    def test_file_not_found_returns_error(self, clean_env, capsys) -> None:
        args = SimpleNamespace(
            api_key="k",
            endpoint=None,
            format=None,
            report_dir=None,
            include_private_ips=False,
            file="/nonexistent/does_not_exist.log",
        )
        assert run_cli(args) == 2
        captured = capsys.readouterr()
        assert "file not found" in captured.err.lower()

    def test_happy_path_writes_report(
        self, clean_env, monkeypatch, capsys, sample_log, tmp_path
    ) -> None:
        args = SimpleNamespace(
            api_key="k",
            endpoint=None,
            format="csv",
            report_dir=str(tmp_path),
            include_private_ips=True,
            file=sample_log,
        )
        monkeypatch.setattr(logscan, "OpenTIPClient", FakeOpenTIPClient)
        assert run_cli(args) == 0
        captured = capsys.readouterr()
        assert "Report generated" in captured.out
        # A CSV report should have been written into tmp_path.
        report_files = list(tmp_path.glob("logscan_report_*.csv"))
        assert len(report_files) == 1

    def test_no_artefacts_returns_zero(self, clean_env, capsys, tmp_path) -> None:
        empty_log = tmp_path / "empty.log"
        empty_log.write_text("just some text with no artefacts\n")
        args = SimpleNamespace(
            api_key="k",
            endpoint=None,
            format="csv",
            report_dir=str(tmp_path),
            include_private_ips=True,
            file=str(empty_log),
        )
        assert run_cli(args) == 0
        captured = capsys.readouterr()
        assert "No IP addresses or hashes found" in captured.out


class TestRunService:
    def test_missing_token_returns_error(self, clean_env, capsys) -> None:
        args = SimpleNamespace()
        assert run_service(args) == 2
        captured = capsys.readouterr()
        assert "TELEGRAM_TOKEN" in captured.err


class TestMain:
    def test_main_cli_mode(
        self, clean_env, monkeypatch, capsys, sample_log, tmp_path
    ) -> None:
        monkeypatch.setenv("OPENTIP_API_KEY", "env-key")
        monkeypatch.setenv("LOGSCAN_REPORT_DIR", str(tmp_path))
        monkeypatch.setattr(logscan, "OpenTIPClient", FakeOpenTIPClient)
        rc = main(["--file", sample_log, "--include-private-ips"])
        assert rc == 0

    def test_main_service_flag_delegates(self, clean_env, monkeypatch, capsys) -> None:
        monkeypatch.setenv("TELEGRAM_TOKEN", "tok")
        # Replace the blocking bot.run() with a no-op.
        called = {}

        class FakeBot:
            def __init__(self, settings):
                self.settings = settings

            def run(self) -> None:
                called["run"] = True

        # run_service() lazily imports `from lib.telegram_bot import LogscanBot`,
        # so patch that module (the top-level `lib` package registered on
        # sys.path by the logscan __init__ module).
        monkeypatch.setattr("lib.telegram_bot.LogscanBot", FakeBot)
        assert main(["--service"]) == 0
        assert called.get("run") is True
