from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from docker_security_auditor import cli as cli_module
from docker_security_auditor.auditor import (
    AuditFinding,
    AuditResult,
    DockerUnavailableError,
    ImageNotFoundError,
    ReportWriteError,
    TrivyInvalidJsonError,
    TrivyScanError,
    TrivyTimeoutError,
    TrivyUnavailableError,
    audit_image,
    build_json_report,
    calculate_risk_score,
    scan_image_vulnerabilities,
    write_json_report,
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


def test_calculate_risk_score_uses_expected_components_and_caps_at_hundred() -> None:
    findings = (
        AuditFinding(check="tag", status="MEDIUM", message="Uses the mutable 'latest' tag implicitly."),
        AuditFinding(check="user", status="HIGH", message="Configured user is 'root' (root-equivalent)."),
        AuditFinding(check="healthcheck", status="MEDIUM", message="No health check is configured."),
        AuditFinding(check="secrets", status="HIGH", message="Suspicious environment variables: API_KEY, PASSWORD."),
    )

    score = calculate_risk_score(findings, high_count=25, critical_count=25)

    assert score == 100


def test_calculate_risk_score_for_moderate_findings() -> None:
    findings = (
        AuditFinding(check="tag", status="MEDIUM", message="Uses the mutable 'latest' tag."),
        AuditFinding(check="healthcheck", status="PASS", message="A health check is configured."),
    )

    score = calculate_risk_score(findings, high_count=3, critical_count=1)

    assert score == 10 + 6 + 10


@pytest.mark.parametrize(
    ("status", "expected_exit_code"),
    [
        ("PASS", 0),
        ("INFO", 0),
        ("MEDIUM", 1),
        ("HIGH", 2),
        ("CRITICAL", 3),
    ],
)
def test_main_returns_expected_exit_code_for_severity(status: str, expected_exit_code: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli_module, "audit_image", lambda image_name: AuditResult(findings=(AuditFinding("tag", status, "message"),)))

    exit_code = main(["audit", "alpine"])

    captured = capsys.readouterr()
    assert exit_code == expected_exit_code
    assert status in captured.out


def test_main_returns_operational_error_exit_code(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli_module, "audit_image", lambda image_name: (_ for _ in ()).throw(RuntimeError("boom")))

    exit_code = main(["audit", "alpine"])

    captured = capsys.readouterr()
    assert exit_code == 4
    assert "boom" in captured.err


def test_build_json_report_contains_expected_fields_and_no_secret_values() -> None:
    result = AuditResult(
        findings=(
            AuditFinding(check="tag", status="MEDIUM", message="Uses the mutable 'latest' tag implicitly."),
            AuditFinding(check="user", status="HIGH", message="Configured user is 'root' (root-equivalent)."),
            AuditFinding(check="healthcheck", status="MEDIUM", message="No health check is configured."),
            AuditFinding(check="secrets", status="HIGH", message="Suspicious environment variables: API_KEY, PASSWORD."),
            AuditFinding(check="vulnerabilities", status="CRITICAL", message="HIGH=2 CRITICAL=1 total=3"),
        )
    )

    report = build_json_report("alpine", result, high_count=2, critical_count=1, exit_code=3)

    assert report["schema_version"] == 1
    assert report["image"] == "alpine"
    assert report["overall_severity"] == "CRITICAL"
    assert report["risk_score"] == 84
    assert report["exit_code"] == 3
    assert report["vulnerability_counts"] == {"high": 2, "critical": 1, "total": 3}
    assert report["results"][0]["check"] == "tag"
    assert report["results"][-1]["check"] == "vulnerabilities"
    payload = json.dumps(report)
    assert "abc123" not in payload
    assert "API_KEY=secret" not in payload
    assert "PASSWORD=abc123" not in payload


def test_write_json_report_creates_parent_directories(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "reports" / "audit.json"
    payload = {"schema_version": 1, "image": "alpine"}

    write_json_report(payload, destination)

    assert destination.exists()
    written = json.loads(destination.read_text(encoding="utf-8"))
    assert written["image"] == "alpine"


def test_write_json_report_raises_for_write_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = tmp_path / "audit.json"
    payload = {"schema_version": 1, "image": "alpine"}

    def fail_write_text(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", fail_write_text)

    with pytest.raises(ReportWriteError):
        write_json_report(payload, destination)


def test_main_does_not_write_report_unless_requested(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    monkeypatch.setattr(cli_module, "audit_image", lambda image_name: AuditResult(findings=(AuditFinding("tag", "PASS", "message"),)))

    exit_code = main(["audit", "alpine"])

    assert exit_code == 0
    assert not report_path.exists()


def test_main_redacts_secret_values_from_terminal_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        cli_module,
        "audit_image",
        lambda image_name: AuditResult(
            findings=(AuditFinding("secrets", "HIGH", "Suspicious environment variables: PASSWORD=abc123"),)
        ),
    )

    main(["audit", "alpine"])

    captured = capsys.readouterr()
    assert "abc123" not in captured.out
    assert "PASSWORD=abc123" not in captured.out
    assert "API_KEY=secret" not in captured.out


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
