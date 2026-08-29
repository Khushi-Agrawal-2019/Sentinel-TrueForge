"""
Unit tests for SentinelPR Orchestrator Loop.
"""

from pathlib import Path
import unittest

from orchestrator.killswitch import KillSwitch
from orchestrator.run import Orchestrator


class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent / "demo-repo-fixtures" / "python-demo"
        self.killswitch = KillSwitch(workspace_root=self.fixtures_dir)
        self.killswitch.reset()

    def tearDown(self):
        self.killswitch.reset()

    def test_orchestrator_dry_run_success(self):
        """Verify full orchestrator loop in dry-run mode against demo fixture."""
        orchestrator = Orchestrator(
            repo_path=self.fixtures_dir,
            top_n=2,
            timeout=30,
            dry_run=True
        )
        results = orchestrator.execute()
        self.assertEqual(len(results), 2)
        
        # Verify both candidates were tested in sandbox and passed
        passed_count = sum(1 for r in results if r.sandbox_result.passed)
        self.assertEqual(passed_count, 2)
        self.assertTrue(all(r.status == "DRY_RUN" for r in results))

    def test_orchestrator_aborts_on_killswitch(self):
        """Verify orchestrator aborts when killswitch is triggered."""
        self.killswitch.trigger("Test pre-abort")
        orchestrator = Orchestrator(
            repo_path=self.fixtures_dir,
            top_n=2,
            timeout=30,
            dry_run=True
        )
        results = orchestrator.execute()
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
