"""Input models, validation, and finding serialization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class CloudShieldError(Exception):
    """A user-correctable input or file error."""


RESOURCE_TYPES = {
    "s3_bucket",
    "security_group",
    "iam_policy",
    "cloudtrail_trail",
}


@dataclass(frozen=True)
class Resource:
    resource_id: str
    resource_type: str
    config: dict[str, Any]


@dataclass(frozen=True)
class Scenario:
    schema_version: str
    scenario_id: str
    label: str
    resources: tuple[Resource, ...]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    resource_id: str
    explanation: str
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CloudShieldError(f"{path} must be a JSON object.")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise CloudShieldError(f"{path} must be a JSON array.")
    return value


def _optional_object(parent: dict[str, Any], key: str, path: str) -> dict[str, Any] | None:
    if key not in parent:
        return None
    return _require_object(parent[key], path)


def _optional_string(parent: dict[str, Any], key: str, path: str) -> None:
    if key in parent and not isinstance(parent[key], str):
        raise CloudShieldError(f"{path} must be a string when provided.")


def _validate_string_or_string_list(value: Any, path: str) -> None:
    if isinstance(value, str):
        return
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return
    raise CloudShieldError(f"{path} must be a string or an array of strings.")


def _validate_resource_config(resource_type: str, config: dict[str, Any], path: str) -> None:
    if resource_type == "s3_bucket":
        policy = _optional_object(config, "bucket_policy", f"{path}.bucket_policy")
        if policy is not None and "Statement" in policy:
            statements = _require_list(policy["Statement"], f"{path}.bucket_policy.Statement")
            for index, value in enumerate(statements):
                statement_path = f"{path}.bucket_policy.Statement[{index}]"
                statement = _require_object(value, statement_path)
                _optional_string(statement, "Effect", f"{statement_path}.Effect")
        block = _optional_object(config, "public_access_block", f"{path}.public_access_block")
        _optional_object(config, "default_encryption", f"{path}.default_encryption")
    elif resource_type == "security_group":
        if "ingress" in config:
            entries = _require_list(config["ingress"], f"{path}.ingress")
            for index, value in enumerate(entries):
                entry_path = f"{path}.ingress[{index}]"
                entry = _require_object(value, entry_path)
                _optional_string(entry, "IpProtocol", f"{entry_path}.IpProtocol")
                for key in ("FromPort", "ToPort"):
                    if key in entry and (not isinstance(entry[key], int) or isinstance(entry[key], bool)):
                        raise CloudShieldError(f"{entry_path}.{key} must be an integer when provided.")
                for key in ("CidrIpv4", "CidrIpv6"):
                    _optional_string(entry, key, f"{entry_path}.{key}")
    elif resource_type == "iam_policy":
        policy = _optional_object(config, "policy", f"{path}.policy")
        if policy is not None and "Statement" in policy:
            statements = _require_list(policy["Statement"], f"{path}.policy.Statement")
            for index, value in enumerate(statements):
                statement_path = f"{path}.policy.Statement[{index}]"
                statement = _require_object(value, statement_path)
                _optional_string(statement, "Effect", f"{statement_path}.Effect")
                for key in ("Action", "Resource"):
                    if key in statement:
                        _validate_string_or_string_list(statement[key], f"{statement_path}.{key}")
    elif resource_type == "cloudtrail_trail":
        _optional_object(config, "trail", f"{path}.trail")


def parse_scenario(value: Any, source: str = "input") -> Scenario:
    """Validate parsed JSON against the documented Phase 1 scenario structure."""
    data = _require_object(value, source)
    if data.get("schema_version") != "1.0":
        raise CloudShieldError(f"{source}.schema_version must be '1.0'.")
    scenario_id = data.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise CloudShieldError(f"{source}.scenario_id must be a non-empty string.")
    label = data.get("label")
    if not isinstance(label, str) or label not in {"vulnerable", "secure"}:
        raise CloudShieldError(f"{source}.label must be 'vulnerable' or 'secure'.")
    raw_resources = _require_list(data.get("resources"), f"{source}.resources")
    if not raw_resources:
        raise CloudShieldError(f"{source}.resources must contain at least one resource.")

    resources: list[Resource] = []
    for index, raw_resource in enumerate(raw_resources):
        path = f"{source}.resources[{index}]"
        resource_data = _require_object(raw_resource, path)
        resource_id = resource_data.get("resource_id")
        if not isinstance(resource_id, str) or not resource_id.strip():
            raise CloudShieldError(f"{path}.resource_id must be a non-empty string.")
        resource_type = resource_data.get("resource_type")
        if not isinstance(resource_type, str) or resource_type not in RESOURCE_TYPES:
            accepted = ", ".join(sorted(RESOURCE_TYPES))
            raise CloudShieldError(
                f"{path}.resource_type must be one of: {accepted}; got {resource_type!r}."
            )
        config = _require_object(resource_data.get("config"), f"{path}.config")
        _validate_resource_config(resource_type, config, f"{path}.config")
        resources.append(Resource(resource_id, resource_type, config))

    return Scenario(data["schema_version"], scenario_id, label, tuple(resources))


def load_scenario(path: str | Path) -> Scenario:
    """Load and validate one local JSON scenario file."""
    file_path = Path(path)
    try:
        with file_path.open("r", encoding="utf-8") as file:
            value = json.load(file)
    except FileNotFoundError as error:
        raise CloudShieldError(f"Configuration file not found: {file_path}") from error
    except PermissionError as error:
        raise CloudShieldError(f"Cannot read configuration file: {file_path}") from error
    except UnicodeDecodeError as error:
        raise CloudShieldError(f"Configuration file is not valid UTF-8: {file_path}") from error
    except json.JSONDecodeError as error:
        raise CloudShieldError(
            f"Invalid JSON in {file_path} at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error
    except OSError as error:
        raise CloudShieldError(f"Cannot read configuration file {file_path}: {error.strerror}") from error
    return parse_scenario(value, str(file_path))
