"""Command-line interface for Docker Security Auditor."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from docker_security_auditor import __version__
from docker_security_auditor.auditor import audit_image


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        try:
            result = audit_image(args.image_name)
        except FileNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # pragma: no cover - CLI error handling
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        print(f"{result.status}: {result.message}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
