from docker_security_auditor.cli import build_parser


def test_parser_supports_help_and_version() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "--version" in help_text
    assert "Inspect Docker images for security risks." in help_text
