import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

from cloudshield.api import create_app
from cloudshield.explanations import ExplanationService, ExplanationUnavailable

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "data" / "configs"


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.custom_dir = Path(self.temporary_directory.name) / "custom-configs"
        self.app = create_app(CONFIGS, custom_config_dir=self.custom_dir)
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    @staticmethod
    def _valid_configuration():
        return {
            "schema_version": "1.0",
            "scenario_id": "custom-s3-public-vulnerable",
            "label": "vulnerable",
            "resources": [
                {
                    "resource_id": "example-bucket",
                    "resource_type": "s3_bucket",
                    "config": {
                        "bucket_policy": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::example-bucket/*",
                                }
                            ]
                        },
                        "public_access_block": {
                            "BlockPublicAcls": False,
                            "IgnorePublicAcls": False,
                            "BlockPublicPolicy": False,
                            "RestrictPublicBuckets": False,
                        },
                    },
                }
            ],
        }

    def _create_custom_configuration(self, configuration=None):
        response = self.client.post(
            "/api/configs",
            json={"configuration": configuration or self._valid_configuration()},
        )
        self.assertEqual(response.status_code, 201)
        return response.get_json()["id"]

    def test_dashboard_and_assets_load(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Choose a sample to scan", page.data)
        page.close()
        script = self.client.get("/static/app.js")
        self.assertEqual(script.status_code, 200)
        script.close()
        stylesheet = self.client.get("/static/styles.css")
        self.assertEqual(stylesheet.status_code, 200)
        stylesheet.close()

    def test_lists_only_sample_ids_and_names(self):
        response = self.client.get("/api/configs")
        self.assertEqual(response.status_code, 200)
        configs = response.get_json()
        self.assertEqual(len(configs), 10)
        self.assertEqual(
            configs[0],
            {"id": "cloudtrail-secure", "name": "cloudtrail-secure.json"},
        )
        self.assertTrue(all("/" not in item["id"] and "\\" not in item["id"] for item in configs))

    def test_vulnerable_sample_returns_structured_finding(self):
        response = self.client.post("/api/scan", json={"config_id": "s3-public-vulnerable"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["scenario_id"], "s3-public-vulnerable")
        self.assertEqual(len(payload["findings"]), 1)
        finding = payload["findings"][0]
        self.assertEqual(finding["rule_id"], "CS-S3-001")
        self.assertEqual(finding["rule_name"], "Potential public S3 bucket access")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["resource_id"], "example-bucket")
        self.assertTrue(finding["explanation"])
        self.assertTrue(finding["evidence"])

    def test_secure_sample_returns_no_findings(self):
        response = self.client.post("/api/scan", json={"config_id": "s3-public-secure"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["findings"], [])

    def test_unknown_or_path_like_configuration_is_rejected(self):
        for config_id in ("not-a-sample", "..\\README", ".."):
            with self.subTest(config_id=config_id):
                response = self.client.post("/api/scan", json={"config_id": config_id})
                self.assertEqual(response.status_code, 404)
                self.assertIn("Unknown sample configuration", response.get_json()["error"])

    def test_invalid_request_json_and_missing_id_return_clear_errors(self):
        malformed = self.client.post(
            "/api/scan",
            data='{"config_id":',
            content_type="application/json",
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.get_json()["error"], "Request body is not valid JSON.")

        missing_id = self.client.post("/api/scan", json={"other": "value"})
        self.assertEqual(missing_id.status_code, 400)
        self.assertIn("config_id", missing_id.get_json()["error"])

        non_json = self.client.post("/api/scan", data="config_id=s3-public-secure")
        self.assertEqual(non_json.status_code, 415)

    def test_invalid_sample_json_returns_useful_scanner_error(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "broken.json"
            config_path.write_text('{"schema_version":', encoding="utf-8")
            client = create_app(
                directory,
                custom_config_dir=Path(directory) / "custom-configs",
            ).test_client()
            response = client.post("/api/scan", json={"config_id": "broken"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("Invalid JSON", response.get_json()["error"])
        self.assertNotIn(directory, response.get_json()["error"])

    def test_custom_configuration_crud_and_server_generated_id(self):
        configuration = self._valid_configuration()
        created = self.client.post(
            "/api/configs",
            json={"configuration": configuration},
        )
        self.assertEqual(created.status_code, 201)
        payload = created.get_json()
        config_id = payload["id"]
        self.assertRegex(config_id, r"^custom-[0-9a-f]{32}$")
        self.assertFalse(payload["read_only"])
        self.assertEqual(payload["configuration"], configuration)
        self.assertNotIn(str(self.custom_dir), created.get_data(as_text=True))

        listing = self.client.get("/api/configs").get_json()
        self.assertIn(
            {"id": config_id, "name": f"Custom: {config_id}", "kind": "custom"},
            listing,
        )
        retrieved = self.client.get(f"/api/configs/{config_id}")
        self.assertEqual(retrieved.status_code, 200)
        self.assertEqual(retrieved.get_json()["configuration"], configuration)

        updated_configuration = self._valid_configuration()
        updated_configuration["scenario_id"] = "updated-custom-example"
        updated = self.client.put(
            f"/api/configs/{config_id}",
            json={"configuration": updated_configuration},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(
            self.client.get(f"/api/configs/{config_id}").get_json()["configuration"],
            updated_configuration,
        )

        deleted = self.client.delete(f"/api/configs/{config_id}")
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(
            self.client.get(f"/api/configs/{config_id}").status_code,
            404,
        )

    def test_custom_configuration_is_validated_and_malformed_json_rejected(self):
        malformed = self.client.post(
            "/api/configs",
            data='{"configuration":',
            content_type="application/json",
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertIn("not valid JSON", malformed.get_json()["error"])

        invalid = self._valid_configuration()
        invalid["label"] = "unknown"
        response = self.client.post("/api/configs", json={"configuration": invalid})
        self.assertEqual(response.status_code, 422)
        self.assertIn("label must be", response.get_json()["error"])

        bad_structure = self.client.post(
            "/api/configs",
            json={"configuration": {"schema_version": "1.0"}},
        )
        self.assertEqual(bad_structure.status_code, 422)
        self.assertIn("scenario_id", bad_structure.get_json()["error"])

        supplied_id = self.client.post(
            "/api/configs",
            json={"id": "s3-public-vulnerable", "configuration": self._valid_configuration()},
        )
        self.assertEqual(supplied_id.status_code, 400)
        self.assertIn("assigned by the server", supplied_id.get_json()["error"])

    def test_invalid_custom_update_does_not_replace_saved_configuration(self):
        config_id = self._create_custom_configuration()
        invalid = self._valid_configuration()
        invalid["resources"] = []

        rejected = self.client.put(
            f"/api/configs/{config_id}",
            json={"configuration": invalid},
        )
        self.assertEqual(rejected.status_code, 422)
        self.assertIn("resources must contain at least one resource", rejected.get_json()["error"])

        malformed = self.client.put(
            f"/api/configs/{config_id}",
            data='{"configuration":',
            content_type="application/json",
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(
            self.client.get(f"/api/configs/{config_id}").get_json()["configuration"],
            self._valid_configuration(),
        )

    def test_custom_configuration_rejects_unsafe_and_duplicate_ids(self):
        for path in ("/api/configs/custom-..", "/api/configs/custom-%2e%2e"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertIn(response.status_code, (400, 404))
        self.assertEqual(
            self.client.put(
                "/api/configs/custom-..",
                json={"configuration": self._valid_configuration()},
            ).status_code,
            400,
        )
        self.assertEqual(self.client.delete("/api/configs/custom-..").status_code, 400)

        invalid_scan = self.client.post("/api/scan", json={"config_id": "custom-.."})
        self.assertEqual(invalid_scan.status_code, 404)

        config_id = "custom-" + "a" * 32
        with patch(
            "cloudshield.configurations.uuid.uuid4",
            return_value=SimpleNamespace(hex="a" * 32),
        ):
            first = self.client.post(
                "/api/configs",
                json={"configuration": self._valid_configuration()},
            )
            duplicate = self.client.post(
                "/api/configs",
                json={"configuration": self._valid_configuration()},
            )
        self.assertEqual(first.status_code, 201)
        self.assertEqual(first.get_json()["id"], config_id)
        self.assertEqual(duplicate.status_code, 409)
        self.assertIn("already exists", duplicate.get_json()["error"])

    def test_custom_configuration_can_be_scanned(self):
        config_id = self._create_custom_configuration()
        response = self.client.post("/api/scan", json={"config_id": config_id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["scenario_id"], "custom-s3-public-vulnerable")
        self.assertEqual(response.get_json()["findings"][0]["rule_id"], "CS-S3-001")

    def test_custom_configuration_is_available_to_a_new_app_instance(self):
        config_id = self._create_custom_configuration()
        restarted_app = create_app(
            CONFIGS,
            explanation_service=Mock(),
            custom_config_dir=self.custom_dir,
        ).test_client()

        self.assertIn(
            config_id,
            [item["id"] for item in restarted_app.get("/api/configs").get_json()],
        )
        self.assertEqual(
            restarted_app.get(f"/api/configs/{config_id}").get_json()["configuration"],
            self._valid_configuration(),
        )

    def test_built_in_configurations_cannot_be_updated_or_deleted(self):
        original = (CONFIGS / "s3-public-vulnerable.json").read_bytes()
        config = {"configuration": self._valid_configuration()}
        built_in = self.client.get("/api/configs/s3-public-vulnerable")
        updated = self.client.put("/api/configs/s3-public-vulnerable", json=config)
        deleted = self.client.delete("/api/configs/s3-public-vulnerable")

        self.assertEqual(built_in.status_code, 200)
        self.assertTrue(built_in.get_json()["read_only"])
        self.assertEqual(updated.status_code, 403)
        self.assertIn("read-only", updated.get_json()["error"])
        self.assertEqual(deleted.status_code, 403)
        self.assertIn("cannot be deleted", deleted.get_json()["error"])
        self.assertEqual((CONFIGS / "s3-public-vulnerable.json").read_bytes(), original)

    def test_custom_configuration_uses_existing_mocked_explanation_flow(self):
        config_id = self._create_custom_configuration()
        retriever = Mock()
        retriever.retrieve.return_value = [
            {
                "source_id": "AWS-S3-PUBLIC-ACCESS",
                "title": "Blocking public access to your Amazon S3 storage",
                "publisher": "Amazon Web Services (AWS)",
                "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "topic": "S3 Block Public Access scope and behavior",
                "rule_ids": ["CS-S3-001"],
                "summary": "S3 Block Public Access has four settings.",
                "similarity": 0.8,
            }
        ]
        provider = Mock()
        provider.explain.return_value = (
            "AWS describes these controls [AWS-S3-PUBLIC-ACCESS]."
        )
        self.app.config["EXPLANATION_SERVICE"] = ExplanationService(
            retriever=retriever,
            provider=provider,
        )

        response = self.client.post(
            "/api/explain",
            json={
                "config_id": config_id,
                "rule_id": "CS-S3-001",
                "resource_id": "example-bucket",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["available"])
        self.assertIn("[AWS-S3-PUBLIC-ACCESS]", response.get_json()["explanation"])
        self.assertEqual(
            provider.explain.call_args.args[0]["scenario_id"],
            "custom-s3-public-vulnerable",
        )

    def test_explanation_uses_scanned_finding_and_mocked_llm(self):
        source = {
            "source_id": "AWS-S3-PUBLIC-ACCESS",
            "title": "Blocking public access to your Amazon S3 storage",
            "publisher": "Amazon Web Services (AWS)",
            "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "topic": "S3 Block Public Access scope and behavior",
            "rule_ids": ["CS-S3-001"],
            "summary": "S3 Block Public Access has four settings.",
            "similarity": 0.8,
        }
        retriever = Mock()
        retriever.retrieve.return_value = [source]
        provider = Mock()
        provider.explain.return_value = "AWS describes these controls [AWS-S3-PUBLIC-ACCESS]."
        service = ExplanationService(retriever=retriever, provider=provider)
        client = create_app(CONFIGS, explanation_service=service).test_client()

        response = client.post(
            "/api/explain",
            json={
                "config_id": "s3-public-vulnerable",
                "rule_id": "CS-S3-001",
                "resource_id": "example-bucket",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("[AWS-S3-PUBLIC-ACCESS]", response.get_json()["explanation"])
        self.assertEqual(response.get_json()["sources"][0]["source_id"], "AWS-S3-PUBLIC-ACCESS")
        self.assertEqual(provider.explain.call_args.args[0]["severity"], "High")

    def test_explanation_without_ollama_is_unavailable_not_a_scanner_error(self):
        retriever = Mock()
        retriever.retrieve.return_value = [
            {
                "source_id": "AWS-S3-PUBLIC-ACCESS",
                "title": "Blocking public access to your Amazon S3 storage",
                "publisher": "Amazon Web Services (AWS)",
                "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "topic": "S3 Block Public Access scope and behavior",
                "rule_ids": ["CS-S3-001"],
                "summary": "S3 Block Public Access has four settings.",
                "similarity": 0.8,
            }
        ]
        provider = Mock()
        provider.explain.side_effect = ExplanationUnavailable(
            "Cannot connect to local Ollama. Start Ollama and retry.",
            reason="ollama_unavailable",
        )
        service = ExplanationService(retriever=retriever, provider=provider)
        client = create_app(CONFIGS, explanation_service=service).test_client()

        response = client.post(
            "/api/explain",
            json={
                "config_id": "s3-public-vulnerable",
                "rule_id": "CS-S3-001",
                "resource_id": "example-bucket",
            },
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["reason"], "ollama_unavailable")
        self.assertIn("Start Ollama", response.get_json()["explanation"])

    def test_explanation_rejects_nonexistent_finding(self):
        response = self.client.post(
            "/api/explain",
            json={
                "config_id": "s3-public-secure",
                "rule_id": "CS-S3-001",
                "resource_id": "example-bucket",
            },
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("not present", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
