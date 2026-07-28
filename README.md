# Docker Security Auditor

Docker Security Auditor is a Python CLI project for inspecting Docker images and reporting security risks. The audit command runs Docker image inspection once, Trivy once, and combines the results into a concise summary without generating any report files.

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
- whether the image reference uses the mutable `latest` tag or an explicit digest/tag
- whether the image exposes secret-like environment variables without printing their values
- a Trivy vulnerability summary using `HIGH` and `CRITICAL` counts

### Mutable tag and secret-variable behavior

The audit command inspects the original image reference supplied to the CLI:

- `latest` (or an implicit latest tag) is reported as `MEDIUM`
- an explicit non-latest tag or a digest reference is reported as `PASS`
- suspicious environment variable names such as `PASSWORD`, `TOKEN`, `API_KEY`, `SECRET`, `PRIVATE_KEY`, `ACCESS_KEY`, and `CREDENTIAL` are reported as `HIGH`
- only the variable names are shown, sorted and deduplicated, and their values are never exposed

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
HIGH: tag: Uses the mutable 'latest' tag implicitly. | user: Configured user is 'root' (root-equivalent). | ports: No exposed ports are declared. | healthcheck: No health check is configured. | secrets: PASS: No suspicious environment variables detected. | vulnerabilities: HIGH=2 CRITICAL=0 total=2
```

Critical image with a vulnerable package:

```text
CRITICAL: tag: Uses explicit tag '1.2.3'. | user: Configured user is 'app'. | ports: Exposed ports: 80/tcp. | healthcheck: A health check is configured. | secrets: HIGH: Suspicious environment variables: API_KEY, PASSWORD. | vulnerabilities: HIGH=1 CRITICAL=1 total=2
```

## Next steps

- Add more security checks for image contents and package vulnerabilities
- Expand CLI commands and output formats
