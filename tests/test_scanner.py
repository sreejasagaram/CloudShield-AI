import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloudshield.cli import main
from cloudshield.models import CloudShieldError, load_scenario, parse_scenario
from cloudshield.scanner import scan_file

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "data" / "configs"
EXPECTED_PATH = ROOT / "data" / "expected" / "results.json"


class ScannerTests(unittest.TestCase):
    def test_all_sample_rule_ids_severity_and_evidence_match_expected(self):
        expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))["results"]
        expected_by_id = {result["scenario_id"]: result for result in expected}
        config_paths = sorted(CONFIGS.glob("*.json"))
        self.assertEqual(len(config_paths), len(expected_by_id))

        seen_ids = set()
        for config_path in config_paths:
            with self.subTest(config=config_path.name):
                scenario, findings = scan_file(config_path)
                result = expected_by_id[scenario.scenario_id]
                seen_ids.add(scenario.scenario_id)
                self.assertEqual(scenario.label, result["label"])
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    result["expected_rule_ids"],
                )
                self.assertEqual(
                    [
                        {
                            "rule_id": finding.rule_id,
                            "severity": finding.severity,
                            "evidence": list(finding.evidence),
                        }
                        for finding in findings
                    ],
                    result["findings"],
                )
        self.assertEqual(seen_ids, set(expected_by_id))

    def test_invalid_json_has_useful_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.json"
            path.write_text('{"schema_version":', encoding="utf-8")
            with self.assertRaisesRegex(CloudShieldError, "Invalid JSON.*line 1"):
                load_scenario(path)

    def test_bad_top_level_and_unexpected_resource_type_are_rejected(self):
        with self.assertRaisesRegex(CloudShieldError, "resources must be a JSON array"):
            parse_scenario(
                {
                    "schema_version": "1.0",
                    "scenario_id": "bad",
                    "label": "secure",
                    "resources": {},
                }
            )
        with self.assertRaisesRegex(CloudShieldError, "label must be"):
            parse_scenario(
                {
                    "schema_version": "1.0",
                    "scenario_id": "bad",
                    "label": [],
                    "resources": [],
                }
            )
        with self.assertRaisesRegex(CloudShieldError, "resource_type must be one of"):
            parse_scenario(
                {
                    "schema_version": "1.0",
                    "scenario_id": "bad",
                    "label": "secure",
                    "resources": [
                        {"resource_id": "unknown", "resource_type": "not_supported", "config": {}}
                    ],
                }
            )

    def test_malformed_nested_rule_data_is_rejected_with_path(self):
        value = json.loads((CONFIGS / "network-ingress-secure.json").read_text(encoding="utf-8"))
        value["resources"][0]["config"]["ingress"] = "not-an-array"
        with self.assertRaisesRegex(CloudShieldError, r"config.ingress must be a JSON array"):
            parse_scenario(value)

    def test_unreadable_path_has_useful_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(CloudShieldError, "Cannot read configuration file"):
                load_scenario(directory)

    def test_cli_prints_json_and_returns_error_without_traceback(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main([str(CONFIGS / "s3-public-vulnerable.json"), "--format", "json"])
        self.assertEqual(status, 0)
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["scenario_id"], "s3-public-vulnerable")
        self.assertEqual(output["findings"][0]["rule_id"], "CS-S3-001")
        self.assertEqual(output["findings"][0]["resource_id"], "example-bucket")

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main([str(CONFIGS / "does-not-exist.json")])
        self.assertEqual(status, 2)
        self.assertIn("Configuration file not found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
