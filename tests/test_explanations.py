import json
import os
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from unittest.mock import Mock, patch

from flask import Flask

from cloudshield.api import _explanation_response
from cloudshield.explanations import (
    AgentWorkflowUnavailable,
    DEFAULT_MODEL,
    DEFAULT_OLLAMA_URL,
    INSUFFICIENT_CONTEXT_MESSAGE,
    ExplanationProviderError,
    ExplanationUnavailable,
    ExplanationService,
    OllamaExplanationProvider,
    ReadOnlyExplanationAgent,
)
from cloudshield.retrieval import SourceRetriever

FINDING = {
    "rule_id": "CS-S3-001",
    "rule_name": "Potential public S3 bucket access",
    "severity": "High",
    "resource_id": "example-bucket",
    "explanation": "A public allow principal needs review.",
    "evidence": ["bucket_policy.Statement[0].Principal: *"],
}
SOURCE = {
    "source_id": "AWS-S3-PUBLIC-ACCESS",
    "title": "Blocking public access to your Amazon S3 storage",
    "publisher": "Amazon Web Services (AWS)",
    "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    "topic": "S3 Block Public Access scope and behavior",
    "rule_ids": ["CS-S3-001"],
    "summary": "S3 Block Public Access has four settings and multiple scope levels.",
    "similarity": 0.8,
}


class RetrievalTests(unittest.TestCase):
    def test_tfidf_retrieval_returns_rule_relevant_registered_source(self):
        retriever = SourceRetriever()
        sources = retriever.retrieve(
            "public S3 bucket access block settings account policy principal",
            rule_id="CS-S3-001",
        )
        self.assertEqual([source["source_id"] for source in sources], ["AWS-S3-PUBLIC-ACCESS"])
        self.assertGreaterEqual(sources[0]["similarity"], 0.01)
        self.assertTrue(sources[0]["url"].startswith("https://docs.aws.amazon.com/"))

    def test_unknown_rule_or_unrelated_query_returns_no_source(self):
        retriever = SourceRetriever()
        self.assertEqual(retriever.retrieve("S3 public access", "CS-UNKNOWN"), [])
        self.assertEqual(
            retriever.retrieve("quantum astronomy unrelated glossary", "CS-S3-001"),
            [],
        )

    def test_persistent_vector_index_reopens_with_source_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            persist_directory = Path(directory) / "vector-db"
            script = (
                "import json, sys; "
                "from cloudshield.retrieval import SourceRetriever; "
                "retriever = SourceRetriever(); "
                "sources = retriever.retrieve('S3 bucket public access block settings', "
                "'CS-S3-001'); "
                "print('RESULT:' + json.dumps(sources))"
            )
            environment = os.environ.copy()
            source_path = str(Path(__file__).resolve().parents[1] / "src")
            environment["PYTHONPATH"] = os.pathsep.join(
                filter(None, (source_path, environment.get("PYTHONPATH")))
            )
            environment["CLOUDSHIELD_VECTOR_DB_DIR"] = str(persist_directory)
            process_results = [
                subprocess.run(
                    [sys.executable, "-c", script],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                for _ in range(2)
            ]

        persisted_results = [
            json.loads(
                next(line.removeprefix("RESULT:") for line in process.stdout.splitlines()
                     if line.startswith("RESULT:"))
            )
            for process in process_results
        ]
        self.assertEqual(
            persisted_results[0][0]["source_id"],
            persisted_results[1][0]["source_id"],
        )
        self.assertEqual(
            persisted_results[1][0]["topic"],
            "S3 Block Public Access scope and behavior",
        )
        self.assertEqual(persisted_results[1][0]["rule_ids"], ["CS-S3-001"])


class ExplanationServiceTests(unittest.TestCase):
    def test_agent_has_one_retrieval_tool_and_a_two_step_limit(self):
        agent = ReadOnlyExplanationAgent(Mock(), Mock())

        self.assertEqual(agent.tool_names, ("retrieve_trusted_sources",))
        self.assertEqual(agent.MAX_STEPS, 2)

    def test_retrieved_sources_are_passed_to_mocked_provider_and_cited(self):
        retriever = Mock()
        retriever.retrieve.return_value = [SOURCE]
        provider = Mock()
        provider.explain.return_value = (
            "The policy resembles a public allow. AWS describes Block Public Access controls [AWS-S3-PUBLIC-ACCESS]."
        )
        service = ExplanationService(retriever=retriever, provider=provider)

        result = service.explain_finding(FINDING)

        retriever.retrieve.assert_called_once()
        self.assertEqual(retriever.retrieve.call_args.kwargs["rule_id"], "CS-S3-001")
        provider.explain.assert_called_once_with(FINDING, [SOURCE])
        self.assertTrue(result["available"])
        self.assertIn("[AWS-S3-PUBLIC-ACCESS]", result["explanation"])
        self.assertEqual(result["sources"][0]["source_id"], "AWS-S3-PUBLIC-ACCESS")

    def test_unavailable_local_provider_keeps_clear_unavailable_result(self):
        retriever = Mock()
        retriever.retrieve.return_value = [SOURCE]
        provider = Mock()
        provider.explain.side_effect = ExplanationUnavailable(
            "Cannot connect to local Ollama. Start Ollama and retry.",
            reason="ollama_unavailable",
        )
        service = ExplanationService(retriever=retriever, provider=provider)

        result = service.explain_finding(FINDING)

        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "ollama_unavailable")
        self.assertIn("Start Ollama", result["explanation"])

    def test_insufficient_context_does_not_call_provider(self):
        retriever = Mock()
        retriever.retrieve.return_value = []
        provider = Mock()
        service = ExplanationService(retriever=retriever, provider=provider)

        result = service.explain_finding(FINDING)

        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "insufficient_context")
        self.assertEqual(result["explanation"], INSUFFICIENT_CONTEXT_MESSAGE)
        provider.explain.assert_not_called()

    def test_rejects_citation_not_in_retrieved_sources(self):
        retriever = Mock()
        retriever.retrieve.return_value = [SOURCE]
        provider = Mock()
        provider.explain.return_value = "Claim with invented citation [AWS-IAM-ACCESS-POLICIES]."
        service = ExplanationService(retriever=retriever, provider=provider)

        with self.assertRaisesRegex(ExplanationProviderError, "did not cite only"):
            service.explain_finding(FINDING)

    def test_trusted_source_links_remain_available_without_inline_model_citations(self):
        retriever = Mock()
        retriever.retrieve.return_value = [SOURCE]
        provider = Mock()
        provider.explain.return_value = "Review the policy and restrict access to authorized principals."
        service = ExplanationService(retriever=retriever, provider=provider)

        result = service.explain_finding(FINDING)

        self.assertTrue(result["available"])
        self.assertEqual(result["sources"][0]["source_id"], "AWS-S3-PUBLIC-ACCESS")

    def test_simple_explanation_path_is_used_if_agent_is_unavailable(self):
        retriever = Mock()
        retriever.retrieve.return_value = [SOURCE]
        provider = Mock()
        provider.explain.return_value = (
            "AWS describes Block Public Access settings [AWS-S3-PUBLIC-ACCESS]."
        )
        service = ExplanationService(retriever=retriever, provider=provider)
        service.agent.explain_finding = Mock(
            side_effect=AgentWorkflowUnavailable("Agent workflow unavailable.")
        )

        result = service.explain_finding(FINDING)

        self.assertTrue(result["available"])
        retriever.retrieve.assert_called_once()
        provider.explain.assert_called_once_with(FINDING, [SOURCE])

    def test_ollama_chat_request_uses_local_default_model(self):
        response_text = json.dumps(
            {
                "what_it_means": "A finding.",
                "why_it_matters": "A risk.",
                "possible_impact": "An outcome.",
                "how_to_fix_it": "A mitigation.",
                "recommended_practices": "A practice.",
            }
        )
        response = BytesIO(
            json.dumps({"message": {"content": response_text}}).encode("utf-8")
        )
        with patch("cloudshield.explanations.urlopen", return_value=response) as request:
            provider = OllamaExplanationProvider()
            explanation = provider.explain(FINDING, [SOURCE])

        self.assertEqual(DEFAULT_MODEL, "qwen2.5:3b")
        self.assertIn("### What it means\nA finding.", explanation)
        self.assertIn("### Recommended practices\nA practice.", explanation)
        request_data = request.call_args.args[0]
        self.assertEqual(request_data.full_url, f"{DEFAULT_OLLAMA_URL}/api/chat")
        self.assertEqual(request_data.get_method(), "POST")
        payload = json.loads(request_data.data.decode("utf-8"))
        self.assertEqual(payload["model"], DEFAULT_MODEL)
        self.assertFalse(payload["stream"])
        self.assertIn("what_it_means", payload["format"]["required"])
        user_input = json.loads(payload["messages"][1]["content"])
        self.assertEqual(
            user_input["retrieved_sources"][0]["citation_id"],
            "AWS-S3-PUBLIC-ACCESS",
        )

    def test_ollama_missing_model_has_install_guidance(self):
        error = HTTPError(
            f"{DEFAULT_OLLAMA_URL}/api/chat",
            404,
            "Not Found",
            None,
            BytesIO(b'{"error":"model not found"}'),
        )
        with patch("cloudshield.explanations.urlopen", side_effect=error):
            with self.assertRaises(ExplanationUnavailable) as raised:
                OllamaExplanationProvider().explain(FINDING, [SOURCE])

        self.assertEqual(raised.exception.reason, "model_unavailable")
        self.assertIn("ollama pull qwen2.5:3b", str(raised.exception))

    def test_ollama_output_omits_code_and_preserves_scanner_severity(self):
        response_text = json.dumps(
            {
                "what_it_means": "This finding is critical.",
                "why_it_matters": (
                    "Public access can expose data.\n\n"
                    "CloudTrail logs indicate a separate issue."
                ),
                "possible_impact": (
                    "A risk to data.\n\n"
                    "The host `example-referer` should be trusted."
                ),
                "how_to_fix_it": (
                    "Review the provided policy.\n\n"
                    "The BlockPublicAcls setting is true.\n\n"
                    "Example of a policy:\n"
                    "```json\n{\"Effect\":\"Deny\"}\n```\n"
                    "In this example, use arn:aws:iam::123456789012:user/example."
                ),
                "recommended_practices": "Review access regularly.",
            }
        )
        response = BytesIO(
            json.dumps({"message": {"content": response_text}}).encode("utf-8")
        )
        with patch("cloudshield.explanations.urlopen", return_value=response):
            finding = {
                **FINDING,
                "evidence": ["public_access_block.BlockPublicAcls: false"],
            }
            explanation = OllamaExplanationProvider().explain(finding, [SOURCE])

        self.assertIn("This finding is High.", explanation)
        self.assertNotIn("CloudTrail", explanation)
        self.assertNotIn("example-referer", explanation)
        self.assertNotIn("BlockPublicAcls setting is true", explanation)
        self.assertNotIn("```", explanation)
        self.assertNotIn('"Effect"', explanation)
        self.assertNotIn("arn:aws:", explanation)
        self.assertIn("code/configuration omitted", explanation)
        self.assertIn("did not match the deterministic finding evidence", explanation)

    def test_ollama_connection_failure_has_local_service_guidance(self):
        with patch(
            "cloudshield.explanations.urlopen",
            side_effect=URLError(ConnectionRefusedError("private detail")),
        ):
            with self.assertRaises(ExplanationUnavailable) as raised:
                OllamaExplanationProvider().explain(FINDING, [SOURCE])

        self.assertEqual(raised.exception.reason, "ollama_unavailable")
        self.assertIn("http://localhost:11434", str(raised.exception))
        self.assertNotIn("private detail", str(raised.exception))

    def test_ollama_status_reports_model_not_installed(self):
        response = BytesIO(json.dumps({"models": []}).encode("utf-8"))
        with patch("cloudshield.explanations.urlopen", return_value=response):
            status = OllamaExplanationProvider().check_model_available()

        self.assertFalse(status["available"])
        self.assertIn("ollama pull qwen2.5:3b", status["message"])

    def test_api_returns_safe_provider_diagnostic_instead_of_generic_error(self):
        diagnostic = "The local Ollama provider failed."
        service = Mock()
        service.explain_finding.side_effect = ExplanationProviderError(diagnostic)
        app = Flask(__name__)
        app.config["EXPLANATION_SERVICE"] = service

        with app.test_request_context("/api/explain"):
            response, status = _explanation_response(app, FINDING)

        self.assertEqual(status, 502)
        self.assertEqual(response.get_json()["error"], diagnostic)

    def test_api_reports_unavailable_ollama_as_service_unavailable(self):
        service = Mock()
        service.explain_finding.return_value = {
            "available": False,
            "reason": "model_unavailable",
            "explanation": "Install the local Ollama model and retry.",
            "sources": [],
        }
        app = Flask(__name__)
        app.config["EXPLANATION_SERVICE"] = service

        with app.test_request_context("/api/explain"):
            response, status = _explanation_response(app, FINDING)

        self.assertEqual(status, 503)
        self.assertEqual(response.get_json()["reason"], "model_unavailable")
        self.assertIn("Install the local Ollama model", response.get_json()["explanation"])


if __name__ == "__main__":
    unittest.main()
