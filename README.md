# Rvpa Pentest Toolkit

Rvpa Pentest Toolkit is a modular and non-destructive CLI pentest utility designed for authorized testing only. It supports reconnaissance, HTTP/TLS security checks, a local interception proxy, evidence-based validation, and HTML reporting.

## Project status

This project is designed to run on Python 3.11+ and is compatible with Termux Android and GitHub Codespaces.

## Features

- Reconnaissance: DNS resolution, HTTP metadata collection, passive technology detection.
- Scanner: security headers checks, TLS certificate metadata, non-destructive findings.
- Proxy: local HTTP/HTTPS CONNECT proxy with metadata output and no secret retention.
- Validation: safe, evidence-based PoC validation that stores results in JSON.
- Reporting: professional HTML reports, responsive, with HTML escaping for dynamic content.

## Installation

### Linux / macOS / Codespaces

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Termux Android

```bash
pkg update
pkg install python git clang
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py --help
python main.py recon https://authorized-target.example
python main.py scan https://authorized-target.example -o report.html
python main.py proxy
python main.py proxy --host 127.0.0.1 --port 8080
python main.py validate --title "Finding" --description "Description" --evidence "Evidence"
```

## Example scan

```bash
python main.py scan https://authorized-target.example -o report.html
```

This command performs safe checks and writes an HTML report to `report.html`.

## Scope and safe use

- Only test targets that are explicitly authorized.
- Do not run brute force, password guessing, credential theft, denial-of-service, or active exploitation against public targets.
- This toolkit is intended for labs, internal systems, and explicitly approved targets only.
- Always ensure you have written authorization before scanning systems you do not own or manage.

## Limitations

- HTTPS inspection without TLS interception cannot decrypt application traffic.
- The proxy shows metadata and forwarding behavior but does not inspect or store sensitive data such as passwords, cookies, tokens, or secrets.
- TLS certificate metadata is derived from passive inspection and may vary depending on the server configuration.

## Legal and ethical notice

This toolkit is provided for authorized security testing, education, and defensive research only. The user is solely responsible for complying with local laws, organizational policies, contracts, and authorization boundaries.

## License

MIT
