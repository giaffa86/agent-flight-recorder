from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_flight_recorder.report import generate_report


class ReportTests(unittest.TestCase):
    def test_generates_review_sections(self) -> None:
        events = [
            {
                "type": "command",
                "timestamp": "2026-06-13T00:00:00Z",
                "command": "python -m unittest discover -s tests",
                "exit_code": 0,
                "duration_ms": 123,
                "stdout_tail": "OK",
                "stderr_tail": "",
                "secret_findings": [],
            },
            {
                "type": "snapshot",
                "data": {
                    "changed_files": [
                        {"path": "src/auth/login.py", "status": "M"},
                    ],
                    "diff_stat": "src/auth/login.py | 2 ++",
                },
            },
            {
                "type": "imported_log",
                "source": "claude-code",
                "relative_path": "agent.log",
                "line_count": 3,
                "byte_count": 42,
                "content_tail": "safe log",
                "secret_findings": [],
            },
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            report = generate_report(events, Path(temp_dir), "session-1", include_current_git=False)

        self.assertIn("# AI Agent Activity Report", report)
        self.assertIn("## Risk Signals", report)
        self.assertIn("authentication", report)
        self.assertIn("python -m unittest discover -s tests", report)
        self.assertIn("claude-code", report)


if __name__ == "__main__":
    unittest.main()
