"""Inspect Docker images for basic security risks."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

SUSPICIOUS_ENV_VAR_NAMES = {
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "API_KEY",
    "SECRET",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "CREDENTIAL",
}


class DockerUnavailableError(RuntimeError):
    """Raised when Docker is unavailable on the system."""


class ImageNotFoundError(RuntimeError):
    """Raised when the requested Docker image does not exist locally."""


class TrivyUnavailableError(RuntimeError):
    """Raised when Trivy is not available on the system."""


class TrivyScanError(RuntimeError):
    """Raised when Trivy fails to complete a vulnerability scan."""


class TrivyTimeoutError(RuntimeError):
    """Raised when a Trivy scan exceeds the allowed timeout."""


class TrivyInvalidJsonError(RuntimeError):
    """Raised when Trivy returns invalid JSON output."""


@dataclass(frozen=True)
class AuditFinding:
    """Represents a single audit finding."""

    check: str
    status: str
    message: str


@dataclass(frozen=True)
class AuditResult:
    """Represents the outcome of auditing an image."""

    findings: tuple[AuditFinding, ...]

    @property
    def status(self) -> str:
        """Return the highest-severity status across the findings."""
        if any(finding.status == "CRITICAL" for finding in self.findings):
            return "CRITICAL"
        if any(finding.status == "HIGH" for finding in self.findings):
            return "HIGH"
        if any(finding.status == "MEDIUM" for finding in self.findings):
            return "MEDIUM"
        if any(finding.status == "INFO" for finding in self.findings):
            return "INFO"
        return "PASS"

    @property
    def message(self) -> str:
        """Return a single summary line for the result."""
        return " | ".join(f"{finding.check}: {finding.message}" for finding in self.findings)


def _default_docker_runner(image_name: str) -> subprocess.CompletedProcess[str]:
    """Run docker image inspect without shell=True."""
    return subprocess.run(
        ["docker", "image", "inspect", image_name],
        capture_output=True,
        text=True,
        check=False,
    )


def _default_trivy_runner(image_name: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run Trivy with an argument list and shell=False."""
    return subprocess.run(
        [
            "trivy",
            "image",
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "--format",
            "json",
            "--quiet",
            image_name,
        ],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=timeout,
    )


def scan_image_vulnerabilities(
    image_name: str,
    trivy_runner: Optional[Callable[[str, int], subprocess.CompletedProcess[str]]] = None,
    timeout: int = 60,
) -> tuple[int, int]:
    """Run Trivy once per audit and summarize the vulnerability counts."""
    runner = trivy_runner or _default_trivy_runner

    try:
        completed = runner(image_name, timeout)
    except FileNotFoundError as exc:
        raise TrivyUnavailableError("Trivy is not available on this system.") from exc
    except subprocess.TimeoutExpired as exc:
        raise TrivyTimeoutError(f"Trivy scan timed out for image '{image_name}'.") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise TrivyScanError(stderr or f"Trivy scan failed for image '{image_name}'.")

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TrivyInvalidJsonError("Trivy returned invalid JSON for vulnerability scanning.") from exc

    if not isinstance(payload, dict):
        raise TrivyInvalidJsonError("Trivy returned unexpected JSON structure for vulnerability scanning.")

    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise TrivyInvalidJsonError("Trivy returned unexpected JSON structure for vulnerability scanning.")

    high_count = 0
    critical_count = 0
    for result in results:
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            severity = str(vulnerability.get("Severity", "")).upper()
            if severity == "HIGH":
                high_count += 1
            elif severity == "CRITICAL":
                critical_count += 1

    return high_count, critical_count


def _evaluate_image_tag(reference: str) -> tuple[str, str]:
    """Return the tag status and message for an image reference."""
    if "@" in reference:
        return "PASS", "Explicit digest reference; tag immutability is preserved."

    name = reference.rsplit("/", 1)[-1]
    last_segment = name.rsplit(":", 1)
    if len(last_segment) == 2 and ":" in reference.rsplit("/", 1)[-1]:
        tag = last_segment[-1]
        if tag.lower() == "latest":
            return "MEDIUM", "Uses the mutable 'latest' tag."
        return "PASS", f"Uses explicit tag '{tag}'."

    if ":" in reference:
        registry_part, _, _ = reference.rpartition(":")
        if "/" not in registry_part:
            return "MEDIUM", "Uses the mutable 'latest' tag implicitly."

    return "MEDIUM", "Uses the mutable 'latest' tag implicitly."


def _evaluate_secret_variables(env_vars: object) -> tuple[str, str]:
    """Return the secret-variable status and message without exposing values."""
    if not isinstance(env_vars, list):
        return "PASS", "No suspicious environment variables detected."

    suspicious_names: set[str] = set()
    for entry in env_vars:
        if not isinstance(entry, str):
            continue
        if "=" not in entry:
            continue
        name, value = entry.split("=", 1)
        if not name or not value:
            continue
        normalized_name = name.strip().upper()
        if normalized_name in SUSPICIOUS_ENV_VAR_NAMES:
            suspicious_names.add(normalized_name)
        elif any(
            marker in normalized_name
            for marker in ("PASSWORD", "PASSWD", "TOKEN", "SECRET", "CREDENTIAL")
        ):
            suspicious_names.add(normalized_name)
        elif normalized_name.endswith("_KEY") and "API" in normalized_name:
            suspicious_names.add(normalized_name)

    if not suspicious_names:
        return "PASS", "No suspicious environment variables detected."

    sorted_names = ", ".join(sorted(suspicious_names))
    return "HIGH", f"Suspicious environment variables: {sorted_names}."


def audit_image(
    image_name: str,
    docker_runner: Optional[Callable[[str], subprocess.CompletedProcess[str]]] = None,
    trivy_runner: Optional[Callable[[str, int], subprocess.CompletedProcess[str]]] = None,
    timeout: int = 60,
) -> AuditResult:
    """Inspect a local Docker image and report multiple configuration checks."""
    runner = docker_runner or _default_docker_runner

    try:
        completed = runner(image_name)
    except FileNotFoundError as exc:
        raise DockerUnavailableError("Docker is not available on this system.") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        if "No such image" in stderr or "not found" in stderr.lower():
            raise ImageNotFoundError(f"Image '{image_name}' was not found locally.") from exc
        raise RuntimeError(stderr or f"Docker inspect failed for image '{image_name}'.") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        if "No such image" in stderr or "not found" in stderr.lower():
            raise ImageNotFoundError(f"Image '{image_name}' was not found locally.")
        raise RuntimeError(stderr or f"Docker inspect failed for image '{image_name}'.")

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Docker returned invalid JSON for image inspection.") from exc

    if not isinstance(payload, list) or not payload:
        raise RuntimeError("Docker inspect did not return any image metadata.")

    config = payload[0].get("Config", {})
    findings: list[AuditFinding] = []

    tag_status, tag_message = _evaluate_image_tag(image_name)
    findings.append(AuditFinding(check="tag", status=tag_status, message=tag_message))

    env_vars = config.get("Env") or []
    secret_status, secret_message = _evaluate_secret_variables(env_vars)
    findings.append(AuditFinding(check="secrets", status=secret_status, message=secret_message))

    user = config.get("User", "")
    if user in {"", "root", "0"}:
        findings.append(
            AuditFinding(
                check="user",
                status="HIGH",
                message=f"Configured user is '{user or 'empty'}' (root-equivalent).",
            )
        )
    else:
        findings.append(AuditFinding(check="user", status="PASS", message=f"Configured user is '{user}'."))

    exposed_ports = config.get("ExposedPorts") or {}
    if exposed_ports:
        ports = sorted(exposed_ports.keys())
        findings.append(AuditFinding(check="ports", status="INFO", message=f"Exposed ports: {', '.join(ports)}."))
    else:
        findings.append(AuditFinding(check="ports", status="INFO", message="No exposed ports are declared."))

    healthcheck = config.get("Healthcheck") or {}
    if isinstance(healthcheck, dict) and healthcheck.get("Test"):
        test_value = healthcheck.get("Test")
        if isinstance(test_value, list) and test_value == ["NONE"]:
            findings.append(
                AuditFinding(
                    check="healthcheck",
                    status="MEDIUM",
                    message="Health check is explicitly disabled with ['NONE'].",
                )
            )
        else:
            findings.append(
                AuditFinding(
                    check="healthcheck",
                    status="PASS",
                    message="A health check is configured.",
                )
            )
    else:
        findings.append(
            AuditFinding(
                check="healthcheck",
                status="MEDIUM",
                message="No health check is configured.",
            )
        )

    high_count, critical_count = scan_image_vulnerabilities(image_name, trivy_runner=trivy_runner, timeout=timeout)
    vulnerability_status = "PASS"
    if critical_count > 0:
        vulnerability_status = "CRITICAL"
    elif high_count > 0:
        vulnerability_status = "HIGH"

    findings.append(
        AuditFinding(
            check="vulnerabilities",
            status=vulnerability_status,
            message=f"HIGH={high_count} CRITICAL={critical_count} total={high_count + critical_count}",
        )
    )

    return AuditResult(findings=tuple(findings))
