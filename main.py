#!/usr/bin/env python3
"""Rvpa Pentest Toolkit CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys

from core.exceptions import ValidationError
from core.logger import get_logger
from core.orchestrator import Orchestrator


LOGGER = get_logger("main")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Rvpa Pentest Toolkit - modular and safe security testing utilities.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a non-destructive reconnaissance and scan workflow.")
    scan_parser.add_argument("target", help="Target URL to assess, e.g. https://authorized-target.example")
    scan_parser.add_argument("-o", "--output", default="report.html", help="HTML report output file (default: report.html)")

    recon_parser = subparsers.add_parser("recon", help="Perform reconnaissance and metadata collection.")
    recon_parser.add_argument("target", help="Target URL to assess")

    proxy_parser = subparsers.add_parser("proxy", help="Start the interception proxy.")
    proxy_parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    proxy_parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")

    validate_parser = subparsers.add_parser("validate", help="Validate a finding with evidence-based metadata.")
    validate_parser.add_argument("--title", required=True, help="Finding title")
    validate_parser.add_argument("--description", required=True, help="Finding description")
    validate_parser.add_argument("--evidence", required=True, help="Evidence string or note")
    validate_parser.add_argument("-o", "--output", default="validation_results.json", help="JSON output file for the validation result")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    orchestrator = Orchestrator()

    try:
        if args.command == "scan":
            findings = orchestrator.run_scan(args.target)
            output_path = orchestrator.generate_html_report(args.target, findings, args.output)
            print(f"Scan completed for {args.target}.")
            print(f"HTML report saved to: {output_path}")
            return 0

        if args.command == "recon":
            result = orchestrator.run_recon(args.target)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.command == "proxy":
            orchestrator.run_proxy(args.host, args.port)
            return 0

        if args.command == "validate":
            result = orchestrator.validate_finding(args.title, args.description, args.evidence, args.output)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        parser.error("Unknown command")
        return 2

    except ValidationError as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - safety path
        LOGGER.exception("Unhandled application error")
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
