from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


APP_DIR = Path(__file__).resolve().parents[1]


class FrontendBehaviorTests(unittest.TestCase):
    def test_collector_transitions_and_evidence_labels(self) -> None:
        node = shutil.which("node")
        assert node is not None, "Node.js is required to run the frontend behavior checks"
        result = subprocess.run(
            [node, str(APP_DIR / "tests" / "frontend_behavior.cjs")],
            cwd=APP_DIR,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
