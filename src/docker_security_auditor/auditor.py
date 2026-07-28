"""Inspect Docker images for basic security risks."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional


class DockerUnavailableError(RuntimeError):
    """Raised when Docker is unavailable on the system."""


class ImageNotFoundError(RuntimeError):
    """Raised when the requested Docker image does not exist locally."""


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


def audit_image(
    image_name: str,
    docker_runner: Optional[Callable[[str], subprocess.CompletedProcess[str]]] = None,
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

    return AuditResult(findings=tuple(findings))
