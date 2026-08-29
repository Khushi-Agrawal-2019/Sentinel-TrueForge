"""
Unit tests for SentinelPR Kill Switch.
"""

from pathlib import Path
import subprocess
import sys
import time
import unittest

from orchestrator.killswitch import KillSwitch
from orchestrator.sandbox import SandboxRunner


class TestKillSwitch(unittest.TestCase):

    def setUp(self):
        self.workspace = Path(__file__).parent.parent
        self.killswitch = KillSwitch(workspace_root=self.workspace)
        self.killswitch.reset()

    def tearDown(self):
        self.killswitch.reset()

    def test_trigger_and_reset(self):
        """Verify trigger sets flag and reset clears it."""
        self.assertFalse(self.killswitch.is_triggered())
        status = self.killswitch.trigger("Test kill")
        self.assertTrue(self.killswitch.is_triggered())
        self.assertTrue(status.is_active)
        self.assertEqual(status.reason, "Test kill")

        self.killswitch.reset()
        self.assertFalse(self.killswitch.is_triggered())

    def test_killswitch_terminates_active_process(self):
        """Verify triggering killswitch kills a running background process immediately."""
        # Spawn a long-running python sleep process
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.killswitch.register_process(proc.pid)

        # Trigger kill switch
        status = self.killswitch.trigger("Emergency halt test")
        self.assertIn(proc.pid, status.terminated_pids)

        # Wait a moment and check process is dead
        time.sleep(0.2)
        self.assertIsNotNone(proc.poll(), "Process should have been terminated")

    def test_sandbox_runner_respects_killswitch(self):
        """Verify sandbox runner refuses to run when killswitch is triggered."""
        self.killswitch.trigger("Abort run")

        runner = SandboxRunner(
            killswitch_checker=self.killswitch.is_triggered
        )

        fixtures_dir = Path(__file__).parent / "demo-repo-fixtures" / "python-demo"
        result = runner.run_verification(
            repo_dir=fixtures_dir,
            package_name="jinja2",
            target_version="3.1.5"
        )

        self.assertFalse(result.passed)
        self.assertTrue(result.aborted_by_killswitch)
        self.assertIn("Kill Switch", result.stderr)


if __name__ == "__main__":
    unittest.main()
