import json
import unittest
from pathlib import Path

from cloudshield.models import parse_scenario
from cloudshield.rules import (
    check_broad_iam_permissions,
    check_cloudtrail_logging,
    check_public_management_ingress,
    check_public_s3_access,
    check_s3_default_encryption,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "data" / "configs"


def load_resource(filename: str):
    value = json.loads((CONFIGS / filename).read_text(encoding="utf-8"))
    return parse_scenario(value).resources[0]


class RuleFixtureTests(unittest.TestCase):
    def test_five_vulnerable_fixtures_trigger_their_rule(self):
        cases = (
            ("s3-public-vulnerable.json", check_public_s3_access, "CS-S3-001"),
            ("s3-encryption-vulnerable.json", check_s3_default_encryption, "CS-S3-002"),
            ("network-ingress-vulnerable.json", check_public_management_ingress, "CS-NET-001"),
            ("iam-wildcard-vulnerable.json", check_broad_iam_permissions, "CS-IAM-001"),
            ("cloudtrail-vulnerable.json", check_cloudtrail_logging, "CS-CT-001"),
        )
        for filename, rule, expected_id in cases:
            with self.subTest(filename=filename):
                finding = rule(load_resource(filename))
                self.assertIsNotNone(finding)
                self.assertEqual(finding.rule_id, expected_id)
                self.assertTrue(finding.evidence)

    def test_five_corrected_fixtures_do_not_trigger_their_rule(self):
        cases = (
            ("s3-public-secure.json", check_public_s3_access),
            ("s3-encryption-secure.json", check_s3_default_encryption),
            ("network-ingress-secure.json", check_public_management_ingress),
            ("iam-wildcard-secure.json", check_broad_iam_permissions),
            ("cloudtrail-secure.json", check_cloudtrail_logging),
        )
        for filename, rule in cases:
            with self.subTest(filename=filename):
                self.assertIsNone(rule(load_resource(filename)))


class RuleEdgeCaseTests(unittest.TestCase):
    def resource(self, resource_type: str, config: dict, resource_id: str = "edge"):
        value = {
            "schema_version": "1.0",
            "scenario_id": "edge-case",
            "label": "secure",
            "resources": [
                {
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "config": config,
                }
            ],
        }
        return parse_scenario(value).resources[0]

    def test_s3_public_block_missing_and_condition_does_not_suppress_public_principal(self):
        resource = self.resource(
            "s3_bucket",
            {
                "bucket_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Condition": {"IpAddress": {"aws:SourceIp": "192.0.2.1/32"}},
                        }
                    ]
                },
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                },
            },
        )
        finding = check_public_s3_access(resource)
        self.assertIsNotNone(finding)
        self.assertIn("bucket_policy.Statement[0].Principal: {\"AWS\":\"*\"}", finding.evidence)
        self.assertIn("public_access_block.RestrictPublicBuckets: missing", finding.evidence)

    def test_encryption_supported_algorithms_and_unsupported_value(self):
        for algorithm in ("AES256", "aws:kms"):
            with self.subTest(algorithm=algorithm):
                resource = self.resource("s3_bucket", {"default_encryption": {"SSEAlgorithm": algorithm}})
                self.assertIsNone(check_s3_default_encryption(resource))
        for algorithm in ("DSSE-KMS", ["AES256"]):
            with self.subTest(unsupported_algorithm=algorithm):
                resource = self.resource("s3_bucket", {"default_encryption": {"SSEAlgorithm": algorithm}})
                finding = check_s3_default_encryption(resource)
                self.assertIsNotNone(finding)
                self.assertTrue(finding.evidence[0].startswith("default_encryption.SSEAlgorithm: "))

    def test_network_checks_ipv6_ranges_and_all_protocol(self):
        resource = self.resource(
            "security_group",
            {
                "ingress": [
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv6": "::/0"},
                    {"IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"},
                ]
            },
        )
        finding = check_public_management_ingress(resource)
        self.assertIsNotNone(finding)
        self.assertIn("ingress[1].IpProtocol: -1", finding.evidence)
        self.assertIn("ingress[1].CidrIpv4: 0.0.0.0/0", finding.evidence)
        self.assertEqual(len(finding.evidence), 2)

    def test_network_flags_ipv6_public_ingress_to_risky_port(self):
        resource = self.resource(
            "security_group",
            {
                "ingress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "CidrIpv6": "::/0",
                    }
                ]
            },
        )

        finding = check_public_management_ingress(resource)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.rule_id, "CS-NET-001")
        self.assertEqual(finding.rule_name, "Public ingress to a management port")
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.resource_id, "edge")
        self.assertEqual(
            finding.evidence,
            ("ingress[0].CidrIpv6: ::/0", "ingress[0].FromPort/ToPort: 22"),
        )

    def test_network_does_not_flag_public_web_port_or_partial_cidr(self):
        resource = self.resource(
            "security_group",
            {
                "ingress": [
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0"},
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "0.0.0.0/1"},
                ]
            },
        )
        self.assertIsNone(check_public_management_ingress(resource))

    def test_iam_wildcard_requires_same_allow_statement_and_all_resource(self):
        resource = self.resource(
            "iam_policy",
            {
                "policy": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:*", "Resource": "bucket-arn"},
                        {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    ]
                }
            },
        )
        self.assertIsNone(check_broad_iam_permissions(resource))

    def test_cloudtrail_missing_and_non_true_values_trigger(self):
        resource = self.resource("cloudtrail_trail", {"trail": {"IsLogging": 1, "S3BucketName": "  "}})
        finding = check_cloudtrail_logging(resource)
        self.assertIsNotNone(finding)
        self.assertIn("trail.IsLogging: 1", finding.evidence)
        self.assertIn("trail.S3BucketName:   ", finding.evidence)


if __name__ == "__main__":
    unittest.main()
