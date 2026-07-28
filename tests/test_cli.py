from __future__ import annotations

import subprocess
from unittest.mock import Mock

import pytest

from docker_security_auditor.auditor import (
    AuditResult,
    DockerUnavailableError,
    ImageNotFoundError,
    audit_image,
)
from docker_security_auditor.cli import build_parser, main


def test_parser_supports_help_and_version() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "--version" in help_text
    assert "audit" in help_text
    assert "Inspect Docker images for security risks." in help_text


def test_audit_image_reports_high_risk_for_root_user() -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "root"}}]',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=runner)

    assert result.status == "HIGH"
    assert any(finding.check == "user" and finding.status == "HIGH" for finding in result.findings)


def test_audit_image_reports_pass_for_non_root_user() -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=runner)

    assert result.status == "MEDIUM"
    assert any(finding.check == "user" and finding.status == "PASS" for finding in result.findings)
    assert any(finding.check == "healthcheck" and finding.status == "MEDIUM" for finding in result.findings)


def test_audit_image_reports_exposed_ports_and_healthcheck() -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app", "ExposedPorts": {"80/tcp": {}}, "Healthcheck": {"Test": ["CMD", "echo", "ok"]}}}]',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=runner)

    assert result.status == "INFO"
    assert any(finding.check == "ports" and "80/tcp" in finding.message for finding in result.findings)
    assert any(finding.check == "healthcheck" and finding.status == "PASS" for finding in result.findings)


def test_audit_image_reports_medium_for_missing_or_disabled_healthcheck() -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app", "Healthcheck": {"Test": ["NONE"]}}}]',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=runner)

    assert result.status == "MEDIUM"
    assert any(finding.check == "healthcheck" and finding.status == "MEDIUM" for finding in result.findings)


def test_audit_image_raises_for_missing_image() -> None:
    runner = Mock(
        side_effect=subprocess.CalledProcessError(
            1,
            ["docker", "image", "inspect", "missing"],
            stderr="Error: No such image: missing",
        )
    )

    with pytest.raises(ImageNotFoundError):
        audit_image("missing", docker_runner=runner)


def test_audit_image_raises_for_unavailable_docker() -> None:
    runner = Mock(side_effect=FileNotFoundError("docker not found"))

    with pytest.raises(DockerUnavailableError):
        audit_image("alpine", docker_runner=runner)


def test_main_audit_command_prints_result(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def fake_audit_image(image_name: str, docker_runner=None) -> AuditResult:
        return AuditResult(
            findings=(
                type("Finding", (), {"check": "user", "status": "PASS", "message": f"User '{image_name}' is configured"})(),
            )
        )

    monkeypatch.setattr("docker_security_auditor.cli.audit_image", fake_audit_image)

    exit_code = main(["audit", "alpine"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "PASS" in captured.out
    assert "alpine" in captured.out
