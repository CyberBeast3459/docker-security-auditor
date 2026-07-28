from __future__ import annotations

import subprocess
from unittest.mock import Mock

import pytest

from docker_security_auditor.auditor import (
    AuditResult,
    DockerUnavailableError,
    ImageNotFoundError,
    TrivyInvalidJsonError,
    TrivyScanError,
    TrivyTimeoutError,
    TrivyUnavailableError,
    audit_image,
    scan_image_vulnerabilities,
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

    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=runner, trivy_runner=trivy_runner)

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

    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=runner, trivy_runner=trivy_runner)

    assert result.status == "MEDIUM"
    assert any(finding.check == "user" and finding.status == "PASS" for finding in result.findings)
    assert any(finding.check == "healthcheck" and finding.status == "MEDIUM" for finding in result.findings)


def test_audit_image_reports_exposed_ports_and_healthcheck() -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine:3.19"],
            returncode=0,
            stdout='[{"Config": {"User": "app", "ExposedPorts": {"80/tcp": {}}, "Healthcheck": {"Test": ["CMD", "echo", "ok"]}}}]',
            stderr="",
        )
    )

    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine:3.19"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine:3.19", docker_runner=runner, trivy_runner=trivy_runner)

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

    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=runner, trivy_runner=trivy_runner)

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

    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "missing"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    with pytest.raises(ImageNotFoundError):
        audit_image("missing", docker_runner=runner, trivy_runner=trivy_runner)


def test_audit_image_raises_for_unavailable_docker() -> None:
    runner = Mock(side_effect=FileNotFoundError("docker not found"))

    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    with pytest.raises(DockerUnavailableError):
        audit_image("alpine", docker_runner=runner, trivy_runner=trivy_runner)


def test_scan_image_vulnerabilities_uses_trivy_subprocess_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured["shell"] = kwargs.get("shell")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout='{"Results": []}', stderr="")

    monkeypatch.setattr("docker_security_auditor.auditor.subprocess.run", fake_run)

    high_count, critical_count = scan_image_vulnerabilities("alpine")

    assert high_count == 0
    assert critical_count == 0
    assert captured["command"][:4] == ["trivy", "image", "--scanners", "vuln"]
    assert captured["shell"] is False


def test_audit_image_reports_vulnerability_summary() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}, {"Severity": "CRITICAL"}]}]}',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)

    vuln_finding = next(finding for finding in result.findings if finding.check == "vulnerabilities")
    assert vuln_finding.status == "CRITICAL"
    assert "HIGH=1" in vuln_finding.message
    assert "CRITICAL=1" in vuln_finding.message
    assert "total=2" in vuln_finding.message


def test_audit_image_raises_for_invalid_trivy_json() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='not-json',
            stderr="",
        )
    )

    with pytest.raises(TrivyInvalidJsonError):
        audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)


def test_audit_image_raises_for_unavailable_trivy() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(side_effect=FileNotFoundError("trivy not found"))

    with pytest.raises(TrivyUnavailableError):
        audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)


def test_audit_image_raises_for_trivy_timeout() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(side_effect=subprocess.TimeoutExpired(cmd=["trivy"], timeout=5))

    with pytest.raises(TrivyTimeoutError):
        audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)


def test_audit_image_raises_for_trivy_scan_failure() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=1,
            stdout="",
            stderr="scan failed",
        )
    )

    with pytest.raises(TrivyScanError):
        audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)


def test_audit_image_marks_latest_tag_as_medium() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine:latest"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine:latest"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine:latest", docker_runner=docker_runner, trivy_runner=trivy_runner)

    tag_finding = next(finding for finding in result.findings if finding.check == "tag")
    assert tag_finding.status == "MEDIUM"
    assert "latest" in tag_finding.message


def test_audit_image_treats_implicit_latest_as_medium() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)

    tag_finding = next(finding for finding in result.findings if finding.check == "tag")
    assert tag_finding.status == "MEDIUM"
    assert "implicitly" in tag_finding.message.lower()


def test_audit_image_handles_registry_port_and_digest_references() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "registry.example.com:5000/app:1.2.3"],
            returncode=0,
            stdout='[{"Config": {"User": "app"}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "registry.example.com:5000/app:1.2.3"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("registry.example.com:5000/app:1.2.3", docker_runner=docker_runner, trivy_runner=trivy_runner)

    tag_finding = next(finding for finding in result.findings if finding.check == "tag")
    assert tag_finding.status == "PASS"
    assert "1.2.3" in tag_finding.message

    digest_result = audit_image(
        "registry.example.com:5000/app@sha256:deadbeef",
        docker_runner=docker_runner,
        trivy_runner=trivy_runner,
    )
    digest_finding = next(finding for finding in digest_result.findings if finding.check == "tag")
    assert digest_finding.status == "PASS"
    assert "digest" in digest_finding.message.lower()


def test_audit_image_reports_secret_variables_without_exposing_values() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app", "Env": ["PASSWORD=abc123", "API_KEY=secret", "EMPTY=", "PASSWORD=abc123", "OTHER=ok"]}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)

    secret_finding = next(finding for finding in result.findings if finding.check == "secrets")
    assert secret_finding.status == "HIGH"
    assert "API_KEY" in secret_finding.message
    assert "PASSWORD" in secret_finding.message
    assert "abc123" not in secret_finding.message
    assert "secret" not in secret_finding.message
    assert secret_finding.message.count("PASSWORD") == 1


def test_audit_image_does_not_flag_generic_gpg_key() -> None:
    docker_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["docker", "image", "inspect", "alpine"],
            returncode=0,
            stdout='[{"Config": {"User": "app", "Env": ["GPG_KEY=abc123", "OTHER=ok"]}}]',
            stderr="",
        )
    )
    trivy_runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=["trivy", "image", "--scanners", "vuln", "alpine"],
            returncode=0,
            stdout='{"Results": []}',
            stderr="",
        )
    )

    result = audit_image("alpine", docker_runner=docker_runner, trivy_runner=trivy_runner)

    secret_finding = next(finding for finding in result.findings if finding.check == "secrets")
    assert secret_finding.status == "PASS"
    assert "No suspicious environment variables detected." in secret_finding.message
    assert "GPG_KEY" not in secret_finding.message
    assert "abc123" not in secret_finding.message


def test_main_audit_command_prints_result(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def fake_audit_image(image_name: str, docker_runner=None, trivy_runner=None, timeout=60) -> AuditResult:
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
