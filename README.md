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
```

## Next steps

- Add image inspection logic
- Integrate Trivy to enrich vulnerability results
- Expand CLI commands and output formats
