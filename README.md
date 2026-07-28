# Docker Security Auditor

Docker Security Auditor is a Python CLI project for inspecting Docker images and reporting security risks. The audit command now runs Trivy once per image scan and adds a concise vulnerability summary without generating any report files.

## Project structure

- src/docker_security_auditor/: Python package source
- tests/: automated tests
- pyproject.toml: packaging and console entry point

## Usage

Run the CLI with:

```bash
python -m docker_security_auditor --help
python -m docker_security_auditor --version
python -m docker_security_auditor audit alpine
```

### Audit checks

The `audit` command inspects a local Docker image and reports:

- the configured user (high risk for root-equivalent users)
- declared exposed ports
- whether the image has a health check configured
- a Trivy vulnerability summary using `HIGH` and `CRITICAL` counts

### Vulnerability scanning behavior

The audit command runs Trivy once per image with:

```bash
trivy image --scanners vuln --severity HIGH,CRITICAL --format json --quiet <image>
```

It parses the JSON payload, counts HIGH and CRITICAL findings across all results, and reports:

- `PASS` when no findings are present
- `HIGH` when only HIGH findings are present
- `CRITICAL` when at least one CRITICAL finding is present

### Example output

High-risk root image:

```text
HIGH: user: Configured user is 'root' (root-equivalent). | ports: No exposed ports are declared. | healthcheck: No health check is configured. | vulnerabilities: HIGH=2 CRITICAL=0 total=2
```

Critical image with a vulnerable package:

```text
CRITICAL: user: Configured user is 'app'. | ports: Exposed ports: 80/tcp. | healthcheck: A health check is configured. | vulnerabilities: HIGH=1 CRITICAL=1 total=2
```

## Next steps

- Add more security checks for image contents and package vulnerabilities
- Expand CLI commands and output formats
