"""logscan — main entry point.

Runs either the CLI mode (analyze a log file and generate a report)
or the Service mode with Telegram bot loop.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

# Ensure the `lib` package is importable regardless of CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.config import load_settings
from lib.log_parser import parse_file
from lib.mock_server import DUMMY_API_KEY, MockOpenTIPServer
from lib.opentip import OpenTIPClient
from lib.report_generator import generate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logscan",
        description="Analyze log files for suspicious IP addresses and "
        "hashes using the Kaspersky OpenTIP Threat Intelligence API.",
    )
    parser.add_argument(
        "--service",
        action="store_true",
        help="Run in service mode (Telegram bot loop).",
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="Log file to analyze (interactive mode).",
    )
    parser.add_argument(
        "--api-key",
        metavar="KEY",
        help="OpenTIP API key (overrides OPENTIP_API_KEY).",
    )
    parser.add_argument(
        "--endpoint",
        metavar="URL",
        help="OpenTIP API endpoint (overrides OPENTIP_ENDPOINT).",
    )
    parser.add_argument(
        "--format",
        metavar="FORMAT",
        choices=["csv", "json"],
        help="Report format (overrides LOGSCAN_REPORT_FORMAT).",
    )
    parser.add_argument(
        "--report-dir",
        metavar="PATH",
        help="Report output directory (overrides LOGSCAN_REPORT_DIR).",
    )
    parser.add_argument(
        "--include-private-ips",
        action="store_true",
        help="Include private/reserved IP ranges in analysis.",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run against an in-process mock OpenTIP server (no API key required).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def run_cli(args: argparse.Namespace) -> int:
    """Run in CLI mode"""
    settings = load_settings(args)

    mock_server: MockOpenTIPServer | None = None
    if settings.use_mock:
        # Run against an in-process mock so no real API key is required.
        mock_server = MockOpenTIPServer().start()
        settings.opentip_endpoint = mock_server.url
        settings.opentip_api_key = DUMMY_API_KEY
        print(f"Using in-process mock OpenTIP server at {mock_server.url}")

    try:
        if not settings.is_analysis_configured():
            print(
                "Error: analysis is not configured. Set OPENTIP_API_KEY or pass --api-key.",
                file=sys.stderr,
            )
            return 2

        file_path = args.file
        if not file_path:
            file_path = input("Path to log file: ").strip()
            if not file_path:
                print("No file provided.", file=sys.stderr)
                return 2

        if not Path(file_path).is_file():
            print(f"Error: file not found: {file_path}", file=sys.stderr)
            return 2

        print(f"Parsing {file_path} ...")
        artefacts = parse_file(
            file_path, include_private_ips=settings.include_private_ips
        )
        total = len(artefacts["ips"]) + len(artefacts["hashes"])
        print(
            f"Found {len(artefacts['ips'])} IP(s), {len(artefacts['hashes'])} hash(es)."
        )

        if total == 0:
            print("No IP addresses or hashes found in the log.")
            return 0

        client = OpenTIPClient(
            api_key=settings.opentip_api_key,
            endpoint=settings.opentip_endpoint,
            backoff_interval=settings.opentip_backoff_interval,
            max_retries=settings.opentip_max_retries,
        )

        print("Submitting artefacts to OpenTIP ...")
        results = client.analyze(artefacts)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(
            Path(settings.report_dir)
            / f"logscan_report_{timestamp}.{settings.report_format}"
        )
        abs_path = generate(results, settings.report_format, output_path)

        print(f"\nReport generated: {abs_path}\n")
        for record in results:
            print(f"  {record['artefact']:<70} {record['result']}")

        return 0
    finally:
        if mock_server is not None:
            mock_server.stop()


def run_service(args: argparse.Namespace) -> int:
    """Run Telegram bot service loop."""
    settings = load_settings(args)
    if not settings.is_bot_configured():
        print(
            "Error: service mode requires a Telegram token (TELEGRAM_TOKEN).",
            file=sys.stderr,
        )
        return 2

    from lib.telegram_bot import LogscanBot

    bot = LogscanBot(settings)
    print("Starting logscan service (Telegram bot) ...")
    bot.run()
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.service:
        return run_service(args)

    # Interactive mode: run the CLI analysis flow.
    return run_cli(args)


if __name__ == "__main__":
    raise SystemExit(main())
