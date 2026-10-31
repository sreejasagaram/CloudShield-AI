"""Deterministic checks for the five Phase 1 configuration rules."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from cloudshield.models import Finding, Resource

PUBLIC_BLOCK_FIELDS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
RISKY_MANAGEMENT_PORTS = (22, 23, 445, 1433, 3306, 3389, 5432, 5900)


def _display(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _finding(
    rule_id: str,
    rule_name: str,
    severity: str,
    resource: Resource,
    explanation: str,
    evidence: list[str],
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        resource_id=resource.resource_id,
        explanation=explanation,
        evidence=tuple(evidence),
    )


def check_public_s3_access(resource: Resource) -> Finding | None:
    if resource.resource_type != "s3_bucket":
        return None
    config = resource.config
    evidence: list[str] = []
    policy = config.get("bucket_policy", {})
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    for index, statement in enumerate(statements):
        principal = statement.get("Principal")
        public_principal = principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") == "*"
        )
        if statement.get("Effect") == "Allow" and public_principal:
            evidence.append(
                f"bucket_policy.Statement[{index}].Principal: {_display(principal)}"
            )

    block = config.get("public_access_block", {})
    block = block if isinstance(block, dict) else {}
    for field in PUBLIC_BLOCK_FIELDS:
        value = block.get(field)
        if value is not True:
            rendered = "missing" if field not in block else _display(value)
            evidence.append(f"public_access_block.{field}: {rendered}")

    if not evidence:
        return None
    return _finding(
        "CS-S3-001",
        "Potential public S3 bucket access",
        "High",
        resource,
        "A public allow principal or an incomplete bucket-level public-access block needs review.",
        evidence,
    )


def check_s3_default_encryption(resource: Resource) -> Finding | None:
    if resource.resource_type != "s3_bucket":
        return None
    encryption = resource.config.get("default_encryption")
    algorithm = encryption.get("SSEAlgorithm") if isinstance(encryption, dict) else None
    if isinstance(algorithm, str) and algorithm in {"AES256", "aws:kms"}:
        return None
    if not isinstance(encryption, dict) or "SSEAlgorithm" not in encryption:
        evidence_value = "missing"
    else:
        evidence_value = _display(algorithm)
    return _finding(
        "CS-S3-002",
        "S3 default encryption not recognized",
        "Medium",
        resource,
        "The fixture does not specify a supported S3 default-encryption algorithm.",
        [f"default_encryption.SSEAlgorithm: {evidence_value}"],
    )


def check_public_management_ingress(resource: Resource) -> Finding | None:
    if resource.resource_type != "security_group":
        return None
    evidence: list[str] = []
    for index, ingress in enumerate(resource.config.get("ingress", [])):
        protocol = ingress.get("IpProtocol")
        ipv4_public = ingress.get("CidrIpv4") == "0.0.0.0/0"
        ipv6_public = ingress.get("CidrIpv6") == "::/0"
        if not (ipv4_public or ipv6_public):
            continue
        if protocol not in {"tcp", "udp", "-1"}:
            continue
        if protocol == "-1":
            risky_port = "all ports (-1)"
        else:
            start = ingress.get("FromPort")
            end = ingress.get("ToPort")
            matches = [
                port for port in RISKY_MANAGEMENT_PORTS
                if isinstance(start, int)
                and not isinstance(start, bool)
                and isinstance(end, int)
                and not isinstance(end, bool)
                and start <= port <= end
            ]
            if not matches:
                continue
            risky_port = str(matches[0]) if start == end else f"{start}-{end}"
        if ipv4_public:
            evidence.append(f"ingress[{index}].CidrIpv4: 0.0.0.0/0")
        if ipv6_public:
            evidence.append(f"ingress[{index}].CidrIpv6: ::/0")
        if protocol == "-1":
            evidence.append(f"ingress[{index}].IpProtocol: -1")
        else:
            evidence.append(f"ingress[{index}].FromPort/ToPort: {risky_port}")

    if not evidence:
        return None
    return _finding(
        "CS-NET-001",
        "Public ingress to a management port",
        "High",
        resource,
        "Public ingress includes a selected administrative or data-service port.",
        evidence,
    )


def _as_values(value: str | list[str]) -> list[str]:
    return [value] if isinstance(value, str) else value


def check_broad_iam_permissions(resource: Resource) -> Finding | None:
    if resource.resource_type != "iam_policy":
        return None
    evidence: list[str] = []
    policy = resource.config.get("policy", {})
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue
        actions = _as_values(statement.get("Action", []))
        wildcard_action = next(
            (
                action for action in actions
                if action == "*" or re.fullmatch(r"[^:]+:\*", action) is not None
            ),
            None,
        )
        resources = _as_values(statement.get("Resource", []))
        if wildcard_action is not None and "*" in resources:
            evidence.append(f"policy.Statement[{index}].Action: {wildcard_action}")
            evidence.append(f"policy.Statement[{index}].Resource: *")
    if not evidence:
        return None
    return _finding(
        "CS-IAM-001",
        "Broad IAM action and resource wildcard",
        "High",
        resource,
        "One allow statement combines a whole-service or all-action wildcard with all resources.",
        evidence,
    )


def check_cloudtrail_logging(resource: Resource) -> Finding | None:
    if resource.resource_type != "cloudtrail_trail":
        return None
    trail = resource.config.get("trail", {})
    trail = trail if isinstance(trail, dict) else {}
    evidence: list[str] = []
    required_flags = (
        "IsLogging",
        "IsMultiRegionTrail",
        "LogFileValidationEnabled",
        "ManagementEventsReadWrite",
    )
    for field in required_flags:
        if trail.get(field) is not True:
            rendered = "missing" if field not in trail else _display(trail[field])
            evidence.append(f"trail.{field}: {rendered}")
    bucket = trail.get("S3BucketName")
    if not isinstance(bucket, str) or not bucket.strip():
        rendered = "missing" if "S3BucketName" not in trail else _display(bucket)
        evidence.append(f"trail.S3BucketName: {rendered}")
    if not evidence:
        return None
    return _finding(
        "CS-CT-001",
        "CloudTrail trail settings incomplete",
        "Medium",
        resource,
        "One or more required fields in the simplified CloudTrail trail configuration need review.",
        evidence,
    )


Rule = Callable[[Resource], Finding | None]
RULES: tuple[Rule, ...] = (
    check_public_s3_access,
    check_s3_default_encryption,
    check_public_management_ingress,
    check_broad_iam_permissions,
    check_cloudtrail_logging,
)


def scan_resource(resource: Resource) -> list[Finding]:
    """Run all applicable rules in a fixed order for one validated resource."""
    findings = [finding for rule in RULES if (finding := rule(resource)) is not None]
    return findings
