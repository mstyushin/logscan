"""Log parsing utilities.

Extracts suspicious artefacts (IP addresses and hashes) from log content.
"""

from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from typing import Dict, List

# IPv4 with octet validation (0-255 per octet).
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_PATTERN = re.compile(rf"\b(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}\b")

# Conservative, best-effort IPv6 pattern (matches the common textual forms).
# Handles full and compressed groups with an optional trailing zone index.
# Alternatives ending in a hex group are listed before the trailing-"::"
# forms so that greedy matching does not truncate addresses such as
# "2001:db8::1" into the valid-but-incomplete "2001:db8::".
#
# Actually, at some point I thought about throwing away this functionality
# because initially I developed it for VirusTotal and OpenTIP doesn't support
# IPv6 lookups, but so much effort have been already put in these regexps...
#
_IPV6_ALTERNATIVES = (
    # Full 8-group form: 1:2:3:4:5:6:7:8
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    # Compressed forms ending in a single hex group: 2001:db8::1
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
    # Leading "::" forms: ::1, ::
    r"|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)"
    # Trailing "::" forms: 1:2:3:4:5:6:7::
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
)
# Use negative lookarounds instead of \b because IPv6 addresses may legally
# start or end with ":" (e.g. ::1 or a trailing ::). A zone index suffix
# (%eth0, %1, ...) is permitted after the address.
IPV6_PATTERN = re.compile(
    rf"(?<![0-9a-fA-F:])(?:{_IPV6_ALTERNATIVES})(?:%[0-9a-zA-Z._-]+)?"
    r"(?![0-9a-fA-F:])"
)

# Hashes: MD5 (32), SHA-1 (40), SHA-256 (64).
HASH_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
HASH_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Combined hash pattern for a single-pass extraction.
_HASH_COMBINED = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")


def _is_private_ipv4(address: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_private_ipv6(address: str) -> bool:
    # Strip any zone index before parsing.
    raw = address.split("%", 1)[0]
    try:
        ip = ipaddress.IPv6Address(raw)
    except ipaddress.AddressValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def extract_artefacts(
    log_content: str, include_private_ips: bool = False
) -> Dict[str, List[str]]:
    """Extract IPs and hashes from ``log_content``.

    Returns a dict with ``ips`` and ``hashes`` keys, each a de-duplicated
    list in order of first appearance.

    Args:
        log_content: Raw text to scan.
        include_private_ips: When True, include private/reserved IP ranges;
            otherwise they are filtered out.

    Returns:
        A dict like ``{"ips": [...], "hashes": [...]}``.
    """
    if not log_content:
        return {"ips": [], "hashes": []}

    ips = _extract_ips(log_content, include_private_ips=include_private_ips)
    hashes = _extract_hashes(log_content)

    return {"ips": ips, "hashes": hashes}


def _extract_ips(log_content: str, include_private_ips: bool) -> List[str]:
    """Extract and deduplicate IPv4/IPv6 addresses in order of appearance."""
    seen = OrderedDict()

    for match in IPV4_PATTERN.finditer(log_content):
        value = match.group(0)
        if include_private_ips or not _is_private_ipv4(value):
            seen.setdefault(value, True)

    for match in IPV6_PATTERN.finditer(log_content):
        value = match.group(0)
        # Validate with ipaddress (stripping any zone index) so that only
        # syntactically correct IPv6 addresses are included.
        raw = value.split("%", 1)[0]
        try:
            ipaddress.IPv6Address(raw)
        except ipaddress.AddressValueError:
            continue
        if include_private_ips or not _is_private_ipv6(value):
            seen.setdefault(value, True)

    return list(seen.keys())


def _extract_hashes(log_content: str) -> List[str]:
    """Extract and deduplicate hash strings in order of appearance."""
    seen = OrderedDict()
    for match in _HASH_COMBINED.finditer(log_content):
        # Normalize to lowercase for consistency.
        seen.setdefault(match.group(0).lower(), True)
    return list(seen.keys())


def parse_file(
    file_path: str, include_private_ips: bool = False
) -> Dict[str, List[str]]:
    """Read a log file and extract artefacts from its content.

    Args:
        file_path: Path to the log file.
        include_private_ips: See :func:`extract_artefacts`.

    Returns:
        A dict with ``ips`` and ``hashes`` keys.
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    return extract_artefacts(content, include_private_ips=include_private_ips)
