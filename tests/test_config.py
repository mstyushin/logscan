from __future__ import annotations

import pytest

from logscan.lib.config import (
    DEFAULT_OPENTIP_ENDPOINT,
    DEFAULT_REPORT_DIR,
    SUPPORTED_FORMATS,
    Settings,
    load_settings,
    normalize_format,
    settings_summary,
)


class TestSettings:
    def test_defaults(self) -> None:
        s = Settings()
        assert s.opentip_api_key == ""
        assert s.telegram_token == ""
        assert s.telegram_allowed_chats == []
        assert s.opentip_endpoint == DEFAULT_OPENTIP_ENDPOINT
        assert s.report_format == "csv"
        assert s.report_dir == DEFAULT_REPORT_DIR
        assert s.opentip_backoff_interval == 15
        assert s.opentip_max_retries == 5
        assert s.include_private_ips is False

    def test_is_analysis_configured(self) -> None:
        assert Settings(opentip_api_key="key").is_analysis_configured() is True
        assert Settings().is_analysis_configured() is False

    def test_is_bot_configured(self) -> None:
        assert Settings(telegram_token="tok").is_bot_configured() is True
        assert Settings().is_bot_configured() is False


class TestLoadSettings:
    def test_env_only(self, clean_env, monkeypatch) -> None:
        monkeypatch.setenv("OPENTIP_API_KEY", "env-key")
        monkeypatch.setenv("LOGSCAN_REPORT_FORMAT", "json")
        monkeypatch.setenv("OPENTIP_MAX_RETRIES", "3")
        s = load_settings()
        assert s.opentip_api_key == "env-key"
        assert s.report_format == "json"
        assert s.opentip_max_retries == 3

    def test_cli_overrides_env(self, clean_env, monkeypatch, cli_args) -> None:
        monkeypatch.setenv("OPENTIP_API_KEY", "env-key")
        cli_args.api_key = "cli-key"
        cli_args.format = "csv"
        s = load_settings(cli_args)
        assert s.opentip_api_key == "cli-key"
        assert s.report_format == "csv"

    def test_cli_none_values_fall_back_to_env(
        self, clean_env, monkeypatch, cli_args
    ) -> None:
        monkeypatch.setenv("OPENTIP_ENDPOINT", "https://custom.example/")
        s = load_settings(cli_args)
        assert s.opentip_endpoint == "https://custom.example/"

    def test_include_private_ips_from_cli(self, clean_env, cli_args) -> None:
        cli_args.include_private_ips = True
        s = load_settings(cli_args)
        assert s.include_private_ips is True

    def test_no_env_uses_defaults(self, clean_env) -> None:
        s = load_settings()
        assert s.opentip_api_key == ""
        assert s.opentip_endpoint == DEFAULT_OPENTIP_ENDPOINT
        assert s.report_dir == DEFAULT_REPORT_DIR

    def test_invalid_report_format_raises(self, clean_env, monkeypatch) -> None:
        monkeypatch.setenv("LOGSCAN_REPORT_FORMAT", "xml")
        with pytest.raises(ValueError, match="Unsupported report format"):
            load_settings()


class TestNormalizeFormat:
    @pytest.mark.parametrize("fmt", ["csv", "CSV", " json ", "JSON"])
    def test_valid_formats(self, fmt: str) -> None:
        assert normalize_format(fmt) == fmt.strip().lower()

    def test_unsupported(self) -> None:
        with pytest.raises(ValueError, match="Unsupported report format"):
            normalize_format("xml")

    @pytest.mark.parametrize("fmt", list(SUPPORTED_FORMATS))
    def test_supported_formats_roundtrip(self, fmt: str) -> None:
        assert normalize_format(fmt) == fmt


class TestParseAllowedChats:
    def test_empty(self) -> None:
        assert Settings().telegram_allowed_chats == []

    def test_parses_comma_separated_with_negatives(
        self, clean_env, monkeypatch
    ) -> None:
        monkeypatch.setenv("TELEGRAM_ALLOWED_CHATS", "123456789, -987654321 , bad")
        s = load_settings()
        assert s.telegram_allowed_chats == [123456789, -987654321]

    def test_all_invalid_returns_empty(self, clean_env, monkeypatch) -> None:
        monkeypatch.setenv("TELEGRAM_ALLOWED_CHATS", "abc, , 12x")
        s = load_settings()
        assert s.telegram_allowed_chats == []


class TestAsBoolInt:
    def test_as_bool_true_variants(self, clean_env, monkeypatch) -> None:
        for value in ("1", "true", "TRUE", "yes", "on"):
            monkeypatch.setenv("LOGSCAN_INCLUDE_PRIVATE_IPS", value)
            assert load_settings().include_private_ips is True

    def test_as_bool_false_variants(self, clean_env, monkeypatch) -> None:
        for value in ("0", "false", "no", "off", "garbage"):
            monkeypatch.setenv("LOGSCAN_INCLUDE_PRIVATE_IPS", value)
            assert load_settings().include_private_ips is False

    def test_as_int_invalid_falls_back(self, clean_env, monkeypatch) -> None:
        monkeypatch.setenv("OPENTIP_MAX_RETRIES", "not-a-number")
        assert load_settings().opentip_max_retries == 5


class TestSettingsSummary:
    def test_hides_secrets(self, minimal_settings) -> None:
        summary = settings_summary(minimal_settings)
        assert minimal_settings.opentip_api_key not in summary
        assert "test-api-key" not in summary
        # Booleans should be present.
        assert "analysis configured: True" in summary
