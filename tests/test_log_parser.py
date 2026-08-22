from __future__ import annotations

import pytest

from logscan.lib.log_parser import (
    IPV4_PATTERN,
    extract_artefacts,
    parse_file,
)


class TestExtractIPv4:
    def test_extracts_valid_ipv4(self) -> None:
        content = "connection from 8.8.8.8 and 192.168.1.10"
        result = extract_artefacts(content)
        # Private ranges are filtered out by default.
        assert result["ips"] == ["8.8.8.8"]

    def test_include_private_ips(self) -> None:
        content = "from 8.8.8.8 and 192.168.1.10"
        result = extract_artefacts(content, include_private_ips=True)
        assert result["ips"] == ["8.8.8.8", "192.168.1.10"]

    def test_filters_loopback_and_reserved(self) -> None:
        content = "127.0.0.1 10.0.0.1 169.254.1.1 224.0.0.1 0.0.0.0 1.2.3.4"
        result = extract_artefacts(content)
        assert result["ips"] == ["1.2.3.4"]

    def test_rejects_invalid_octets(self) -> None:
        content = "999.999.999.999 256.1.1.1 1.2.3 1.2.3.4"
        result = extract_artefacts(content)
        assert result["ips"] == ["1.2.3.4"]

    def test_ipv4_pattern_boundaries(self) -> None:
        assert IPV4_PATTERN.findall("addr=1.2.3.4;x") == ["1.2.3.4"]
        # Part of a larger number should not match.
        assert IPV4_PATTERN.findall("1234567890") == []


class TestExtractIPv6:
    def test_full_form(self) -> None:
        content = "2001:0db8:0000:0000:0000:ff00:0042:8329"
        result = extract_artefacts(content, include_private_ips=True)
        assert "2001:0db8:0000:0000:0000:ff00:0042:8329" in result["ips"]

    def test_compressed_form_with_trailing_group(self) -> None:
        content = "fe80::1 2001:db8::1"
        result = extract_artefacts(content, include_private_ips=True)
        assert "2001:db8::1" in result["ips"]
        # fe80:: is link-local, filtered by default but present when included.
        assert "fe80::1" in result["ips"]

    def test_leading_double_colon(self) -> None:
        content = "::1"
        result = extract_artefacts(content, include_private_ips=True)
        assert result["ips"] == ["::1"]

    def test_link_local_filtered_by_default(self) -> None:
        content = "fe80::1"
        result = extract_artefacts(content)
        assert result["ips"] == []

    def test_zone_index_preserved(self) -> None:
        content = "fe80::1%eth0"
        result = extract_artefacts(content, include_private_ips=True)
        assert result["ips"] == ["fe80::1%eth0"]

    def test_invalid_ipv6_rejected(self) -> None:
        # Not a valid IPv6 address per ipaddress even though regex matches.
        content = "gggg::"
        result = extract_artefacts(content)
        assert result["ips"] == []

    def test_ipv6_not_truncated_at_inner_double_colon(self) -> None:
        content = "2001:db8::1"
        result = extract_artefacts(content, include_private_ips=True)
        assert result["ips"] == ["2001:db8::1"]


class TestExtractHashes:
    def test_md5(self) -> None:
        content = "md5=5d41402abc4b2a76b9719d911017c592"
        result = extract_artefacts(content)
        assert result["hashes"] == ["5d41402abc4b2a76b9719d911017c592"]

    def test_sha1(self) -> None:
        content = "a" * 40
        result = extract_artefacts(content)
        assert result["hashes"] == ["a" * 40]

    def test_sha256(self) -> None:
        content = "A0C1413B6F18DEDFAA711722C49E6DACC62D703A592C384E90C4F60AF0FBD307"
        result = extract_artefacts(content)
        assert result["hashes"] == [
            "a0c1413b6f18dedfaa711722c49e6dacc62d703a592c384e90c4f60af0fbd307"
        ]

    def test_normalizes_to_lowercase(self) -> None:
        content = "MD5=ABCDEF0123456789ABCDEF0123456789"
        result = extract_artefacts(content)
        assert result["hashes"] == ["abcdef0123456789abcdef0123456789"]

    def test_deduplicates_and_preserves_order(self) -> None:
        content = f"{'a' * 32} {'b' * 32} {'a' * 32}"
        result = extract_artefacts(content)
        assert result["hashes"] == ["a" * 32, "b" * 32]

    def test_does_not_match_partial_hash(self) -> None:
        content = "a" * 31
        result = extract_artefacts(content)
        assert result["hashes"] == []


class TestExtractArtefactsCombined:
    def test_empty_input(self) -> None:
        assert extract_artefacts("") == {"ips": [], "hashes": []}

    def test_empty_whitespace(self) -> None:
        assert extract_artefacts("   \n\t  ") == {"ips": [], "hashes": []}

    def test_mixed_content(self) -> None:
        content = (
            "conn 8.8.8.8 md5=5d41402abc4b2a76b9719d911017c592 fe80::1 sha1=" + "c" * 40
        )
        result = extract_artefacts(content)
        assert result["ips"] == ["8.8.8.8"]
        assert result["hashes"] == [
            "5d41402abc4b2a76b9719d911017c592",
            "c" * 40,
        ]


class TestParseFile:
    def test_parse_file(self, tmp_path) -> None:
        log = tmp_path / "access.log"
        log.write_text("login 8.8.8.8 hash=5d41402abc4b2a76b9719d911017c592\n")
        result = parse_file(str(log))
        assert result["ips"] == ["8.8.8.8"]
        assert result["hashes"] == ["5d41402abc4b2a76b9719d911017c592"]

    def test_parse_file_missing(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            parse_file(str(tmp_path / "does_not_exist.log"))
