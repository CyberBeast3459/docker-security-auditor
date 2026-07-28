# Docker Security Auditor

Docker Security Auditor is a Python CLI project for inspecting Docker images and reporting security risks. This starter scaffold sets up the package layout, CLI entry point, and test structure for future Trivy integration.

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

### Example output

High-risk root image:

```text
HIGH: user: Configured user is 'root' (root-equivalent). | ports: No exposed ports are declared. | healthcheck: No health check is configured.
```

Medium-risk non-root image missing a health check:

```text
MEDIUM: user: Configured user is 'app'. | ports: Exposed ports: 80/tcp. | healthcheck: No health check is configured.
```

## Next steps

- Add more security checks for image contents and package vulnerabilities
- Integrate Trivy to enrich vulnerability results
- Expand CLI commands and output formats
