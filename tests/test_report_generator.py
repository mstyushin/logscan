from __future__ import annotations

import csv
import json
import os

import pytest

from logscan.lib.report_generator import (
    ReportGeneratorError,
    _sanitize,
    generate,
    generate_csv,
    generate_json,
)


class TestSanitize:
    @pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r", "\u0000"])
    def test_hazardous_prefixes_escaped(self, prefix: str) -> None:
        assert _sanitize(prefix + "abc") == "'" + prefix + "abc"

    def test_safe_string_unchanged(self) -> None:
        assert _sanitize("8.8.8.8") == "8.8.8.8"

    def test_empty_string_unchanged(self) -> None:
        assert _sanitize("") == ""

    def test_non_string_unchanged(self) -> None:
        assert _sanitize(123) == 123
        assert _sanitize(None) is None


class TestGenerateCSV:
    def test_writes_header_and_rows(self, tmp_path, sample_results) -> None:
        out = tmp_path / "report.csv"
        result_path = generate_csv(sample_results, str(out))
        assert result_path == os.path.abspath(str(out))

        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert rows[0] == ["artefact", "result", "date"]
        assert len(rows) == 1 + len(sample_results)
        assert rows[1][0] == "8.8.8.8"

    def test_creates_parent_directories(self, tmp_path) -> None:
        out = tmp_path / "nested" / "deep" / "report.csv"
        generate_csv([], str(out))
        assert out.exists()

    def test_sanitizes_injection_fields(self, tmp_path) -> None:
        out = tmp_path / "report.csv"
        records = [{"artefact": "=CMD()", "result": "+x", "date": "2026-01-01"}]
        generate_csv(records, str(out))
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert rows[1][0] == "'=CMD()"
        assert rows[1][1] == "'+x"

    def test_missing_keys_default_to_empty(self, tmp_path) -> None:
        out = tmp_path / "report.csv"
        generate_csv([{"foo": "bar"}], str(out))
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert rows[1] == ["", "", ""]

    def test_directory_creation_failure_raises(self, tmp_path) -> None:
        # os.makedirs with exist_ok=True fails when a file blocks the path.
        blocking = tmp_path / "block.txt"
        blocking.write_text("x")
        out = blocking / "report.csv"
        with pytest.raises(FileExistsError):
            generate_csv([], str(out))


class TestGenerateJSON:
    def test_writes_json_list(self, tmp_path, sample_results) -> None:
        out = tmp_path / "report.json"
        result_path = generate_json(sample_results, str(out))
        assert result_path == os.path.abspath(str(out))

        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)
        assert data[0]["artefact"] == "8.8.8.8"
        assert set(data[0].keys()) == {"artefact", "result", "date"}

    def test_missing_keys_normalized(self, tmp_path) -> None:
        out = tmp_path / "report.json"
        generate_json([{"other": "value"}], str(out))
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data[0] == {"artefact": "", "result": "", "date": ""}


class TestGenerateDispatcher:
    def test_csv_format(self, tmp_path, sample_results) -> None:
        out = tmp_path / "r.csv"
        generate(sample_results, "csv", str(out))
        assert out.exists()

    def test_json_format(self, tmp_path, sample_results) -> None:
        out = tmp_path / "r.json"
        generate(sample_results, "json", str(out))
        assert out.exists()

    def test_format_is_case_insensitive(self, tmp_path, sample_results) -> None:
        out = tmp_path / "r.json"
        generate(sample_results, " JSON ", str(out))
        assert out.exists()

    def test_unsupported_format(self, tmp_path, sample_results) -> None:
        with pytest.raises(ReportGeneratorError, match="Unsupported report format"):
            generate(sample_results, "xml", str(tmp_path / "r.out"))
