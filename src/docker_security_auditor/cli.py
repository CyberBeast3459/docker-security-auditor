"""Command-line interface for Docker Security Auditor."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from docker_security_auditor import __version__
from docker_security_auditor.auditor import (
    ReportWriteError,
    audit_image,
    build_json_report,
    write_json_report,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="docker-security-auditor",
        description="Inspect Docker images for security risks.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")
    audit_parser = subparsers.add_parser("audit", help="Audit a local Docker image")
    audit_parser.add_argument("image_name", help="Name of the local Docker image to inspect")
    audit_parser.add_argument("--json-report", dest="json_report", help="Optional path for a structured JSON audit report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        try:
            result = audit_image(args.image_name)
        except Exception as exc:  # pragma: no cover - CLI error handling
            print(f"Error: {exc}", file=sys.stderr)
            return 4

        print(f"{result.status}: {result.message} | risk_score={result.risk_score}")
        status_to_exit = {
            "PASS": 0,
            "INFO": 0,
            "MEDIUM": 1,
            "HIGH": 2,
            "CRITICAL": 3,
        }
        exit_code = status_to_exit.get(result.status, 0)

        if args.json_report:
            try:
                report = build_json_report(
                    args.image_name,
                    result,
                    high_count=result.high_vulnerability_count,
                    critical_count=result.critical_vulnerability_count,
                    exit_code=exit_code,
                )
                write_json_report(report, args.json_report)
            except ReportWriteError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 4

        return exit_code

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
