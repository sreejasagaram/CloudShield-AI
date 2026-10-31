"""Scenario loading and deterministic scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudshield.models import Finding, Scenario, load_scenario, parse_scenario
from cloudshield.rules import scan_resource


def scan_scenario(value: Any) -> tuple[Scenario, list[Finding]]:
    """Validate a decoded scenario object and return its findings."""
    scenario = parse_scenario(value)
    findings = [
        finding
        for resource in scenario.resources
        for finding in scan_resource(resource)
    ]
    return scenario, findings


def scan_file(path: str | Path) -> tuple[Scenario, list[Finding]]:
    """Load one local scenario JSON file and run all applicable rules."""
    scenario = load_scenario(path)
    findings = [
        finding
        for resource in scenario.resources
        for finding in scan_resource(resource)
    ]
    return scenario, findings
