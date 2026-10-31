"""Command-line interface for scanning a local JSON scenario."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from cloudshield.models import CloudShieldError
from cloudshield.scanner import scan_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudshield",
        description="Scan one local CloudShield JSON scenario. No cloud account is contacted.",
    )
    parser.add_argument("config", type=Path, help="path to a local scenario JSON file")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        scenario, findings = scan_file(args.config)
    except CloudShieldError as error:
        print(f"cloudshield: error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        output = {
            "scenario_id": scenario.scenario_id,
            "label": scenario.label,
            "findings": [finding.to_dict() for finding in findings],
        }
        print(json.dumps(output, indent=2))
        return 0

    print(f"Scenario: {scenario.scenario_id} ({scenario.label})")
    if not findings:
        print("No findings.")
        return 0
    for finding in findings:
        print(f"\n[{finding.severity}] {finding.rule_id} - {finding.rule_name}")
        print(f"Resource: {finding.resource_id}")
        print(f"Explanation: {finding.explanation}")
        print("Evidence:")
        for item in finding.evidence:
            print(f"  - {item}")
    print(f"\nTotal findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
