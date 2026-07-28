"""Command-line interface for Docker Security Auditor."""

from __future__ import annotations

import argparse

from docker_security_auditor import __version__


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
    return parser


def main() -> int:
    """Run the CLI."""
    parser = build_parser()
    parser.parse_args()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
