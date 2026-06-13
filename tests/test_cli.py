from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_start_wraps_command_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
            (repo / "README.md").write_text("hello\n", encoding="utf-8")

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            start = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_flight_recorder",
                    "--repo",
                    str(repo),
                    "start",
                    "--session",
                    "demo",
                    "--",
                    sys.executable,
                    "-c",
                    "print('DATABASE_PASSWORD=secret')",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(start.returncode, 0, start.stderr)
            sessions = list((repo / ".afr" / "sessions").glob("*.jsonl"))
            self.assertEqual(len(sessions), 1)
            records = [
                json.loads(line)
                for line in sessions[0].read_text(encoding="utf-8").splitlines()
                if line
            ]
            command_records = [record for record in records if record.get("type") == "command"]
            self.assertEqual(len(command_records), 1)
            self.assertIn("[REDACTED]", command_records[0]["stdout_tail"])
            self.assertNotIn("secret", command_records[0]["stdout_tail"])
            self.assertTrue(command_records[0]["secret_findings"])

            report = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent_flight_recorder",
                    "--repo",
                    str(repo),
                    "report",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(report.returncode, 0, report.stderr)
            self.assertIn("# AI Agent Activity Report", report.stdout)


if __name__ == "__main__":
    unittest.main()
