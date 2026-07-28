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
class AuditResult:
    """Represents the outcome of auditing an image."""

    status: str
    message: str


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
    """Inspect a local Docker image and report whether its configured user is root."""
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
    user = config.get("User", "")

    if user in {"", "root", "0"}:
        return AuditResult(status="HIGH", message=f"Configured user is '{user or 'empty'}' (root-equivalent).")

    return AuditResult(status="PASS", message=f"Configured user is '{user}'.")
