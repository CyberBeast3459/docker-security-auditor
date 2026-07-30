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

### Risk scoring

The audit calculates a deterministic score from 0 to 100 based on the checks below:

- mutable latest/implicit-latest tag: +10
- root-equivalent configured user: +25
- missing or disabled health check: +10
- one or more secret-like environment variables: +25 total
- HIGH vulnerabilities: +2 each, capped at +20
- CRITICAL vulnerabilities: +10 each, capped at +40
- declared exposed ports: +0

The final score is capped at 100. The terminal summary prints the score as `risk_score=<value>`, while the overall severity remains based on the highest-severity finding.

### Exit codes

| Severity | Exit code |
| --- | ---: |
| PASS / INFO | 0 |
| MEDIUM | 1 |
| HIGH | 2 |
| CRITICAL | 3 |
| Operational error (Docker/Trivy failure, invalid JSON, timeout, report write failure) | 4 |

The CLI still prints the complete audit result before exiting.

### JSON report export

Use the optional `--json-report` argument to write a structured report alongside the normal concise terminal output:

```bash
python -m docker_security_auditor audit alpine --json-report reports/alpine.json
```

The JSON report includes:

- `schema_version`
- `image`
- `overall_severity`
- `risk_score`
- `exit_code`
- `vulnerability_counts`
- `results` for each check

The payload never includes environment-variable values or other secret values.

Example JSON report excerpt:

```json
{
  "schema_version": 1,
  "image": "alpine",
  "overall_severity": "CRITICAL",
  "risk_score": 84,
  "exit_code": 3,
  "vulnerability_counts": {
    "high": 2,
    "critical": 1,
    "total": 3
  },
  "results": [
    {
      "check": "tag",
      "status": "MEDIUM",
      "message": "Uses the mutable 'latest' tag implicitly."
    }
  ]
}
```

### Safe example output

```text
HIGH: tag: Uses the mutable 'latest' tag implicitly. | user: Configured user is 'root' (root-equivalent). | ports: No exposed ports are declared. | healthcheck: No health check is configured. | secrets: HIGH: Suspicious environment variables: API_KEY, PASSWORD. | vulnerabilities: HIGH=2 CRITICAL=0 total=2 | risk_score=60
```

## Next steps

- Add more security checks for image contents and package vulnerabilities
- Expand CLI commands and output formats
