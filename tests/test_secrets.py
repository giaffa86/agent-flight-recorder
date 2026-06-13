from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_flight_recorder.secrets import MASK, find_secret_indicators, redact


class SecretRedactionTests(unittest.TestCase):
    def test_redacts_sensitive_assignment(self) -> None:
        text = "DATABASE_PASSWORD=super-secret-value"

        redacted = redact(text)

        self.assertIn(f"DATABASE_PASSWORD={MASK}", redacted)
        self.assertNotIn("super-secret-value", redacted)

    def test_reports_secret_indicators_without_values(self) -> None:
        text = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"

        findings = find_secret_indicators(text, "env")

        self.assertTrue(findings)
        self.assertEqual(findings[0].source, "env")


if __name__ == "__main__":
    unittest.main()

