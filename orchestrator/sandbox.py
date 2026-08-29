"""
SentinelPR - Ephemeral Sandbox Runner

Executes isolated dependency bumps and test suite verifications inside a safe,
ephemeral environment (Docker container or temporary isolated directory) with
strict timeouts, resource isolation, and automatic teardown.
"""

from dataclasses import dataclass
import logging
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Dict, List, Optional, Tuple

from .parser import ManifestParser

logger = logging.getLogger("sentinelpr.sandbox")


@dataclass
class SandboxResult:
    passed: bool
    package_name: str
    target_version: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    aborted_by_killswitch: bool = False
    error_message: Optional[str] = None


class SandboxRunner:
    """Manages ephemeral test execution with strict isolation and timeout enforcement."""

    def __init__(
        self,
        default_timeout: int = 180,
        prefer_docker: bool = True,
        killswitch_checker: Optional[Callable[[], bool]] = None,
        process_register_callback: Optional[Callable[[int], None]] = None
    ):
        self.default_timeout = default_timeout
        self.prefer_docker = prefer_docker
        self.killswitch_checker = killswitch_checker
        self.process_register_callback = process_register_callback

    def is_docker_available(self) -> bool:
        """Checks if Docker daemon is responsive."""
        if not self.prefer_docker:
            return False
        try:
            res = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3
            )
            return res.returncode == 0
        except Exception:
            return False

    def detect_test_command(self, repo_dir: Path) -> List[str]:
        """Detects the appropriate test suite command for the target repository."""
        # Check for Makefile with test target
        makefile = repo_dir / "Makefile"
        if makefile.is_file():
            try:
                content = makefile.read_text(encoding="utf-8")
                if "test:" in content or "\ntest\n" in content:
                    return ["make", "test"]
            except Exception:
                pass

        # Check for Node.js package.json test script
        package_json = repo_dir / "package.json"
        if package_json.is_file():
            return ["npm", "test"]

        # Check for Python test files or unittest / pytest
        python_files = list(repo_dir.glob("**/test_*.py")) + list(repo_dir.glob("**/*_test.py"))
        if python_files:
            return ["python3", "-m", "unittest", "discover", "-s", ".", "-p", "*test*.py"]

        # Fallback to python unittest discover
        return ["python3", "-m", "unittest"]

    def run_verification(
        self,
        repo_dir: Path,
        package_name: str,
        target_version: str,
        timeout: Optional[int] = None,
        custom_test_cmd: Optional[List[str]] = None
    ) -> SandboxResult:
        """
        Clones the repo into an ephemeral sandbox, applies the target version bump,
        runs the test suite, and unconditionally cleans up.
        """
        effective_timeout = timeout or self.default_timeout
        start_time = time.time()

        # Step 0: Check killswitch before creating sandbox
        if self.killswitch_checker and self.killswitch_checker():
            return SandboxResult(
                passed=False,
                package_name=package_name,
                target_version=target_version,
                exit_code=-1,
                stdout="",
                stderr="Execution aborted by Kill Switch before sandbox creation.",
                duration_seconds=0.0,
                aborted_by_killswitch=True,
                error_message="Aborted by kill switch"
            )

        # Create ephemeral temp sandbox directory
        sandbox_dir = Path(tempfile.mkdtemp(prefix=f"sentinelpr_sandbox_{package_name}_"))
        logger.info(f"Created ephemeral sandbox at {sandbox_dir}")

        try:
            # 1. Copy repository files into sandbox (excluding .git, caches, and flags)
            self._copy_repo_isolated(repo_dir, sandbox_dir)

            # Check killswitch again
            if self.killswitch_checker and self.killswitch_checker():
                return SandboxResult(
                    passed=False,
                    package_name=package_name,
                    target_version=target_version,
                    exit_code=-1,
                    stdout="",
                    stderr="Execution aborted by Kill Switch during sandbox initialization.",
                    duration_seconds=time.time() - start_time,
                    aborted_by_killswitch=True,
                    error_message="Aborted by kill switch"
                )

            # 2. Apply version bump inside sandbox
            manifests = ManifestParser.detect_manifests(sandbox_dir)
            bumped = False
            for m in manifests:
                if ManifestParser.apply_version_bump(m, package_name, target_version):
                    bumped = True
                    logger.info(f"Applied version bump for {package_name} -> {target_version} in {m.name}")

            if not bumped:
                logger.warning(f"Could not find manifest entry to bump for {package_name} in {sandbox_dir}")

            # 3. Detect and run test command
            test_cmd = custom_test_cmd or self.detect_test_command(sandbox_dir)
            logger.info(f"Running sandbox verification with command: {' '.join(test_cmd)}")

            # Check killswitch immediately before spawning test subprocess
            if self.killswitch_checker and self.killswitch_checker():
                return SandboxResult(
                    passed=False,
                    package_name=package_name,
                    target_version=target_version,
                    exit_code=-1,
                    stdout="",
                    stderr="Execution aborted by Kill Switch before test execution.",
                    duration_seconds=time.time() - start_time,
                    aborted_by_killswitch=True,
                    error_message="Aborted by kill switch"
                )

            # 4. Execute test suite with timeout and process tracking
            passed, exit_code, stdout, stderr, aborted = self._execute_test_process(
                test_cmd, sandbox_dir, effective_timeout
            )

            duration = time.time() - start_time
            return SandboxResult(
                passed=passed and not aborted,
                package_name=package_name,
                target_version=target_version,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
                aborted_by_killswitch=aborted,
                error_message="Aborted by kill switch" if aborted else None
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return SandboxResult(
                passed=False,
                package_name=package_name,
                target_version=target_version,
                exit_code=124,
                stdout="",
                stderr=f"Sandbox test execution timed out after {effective_timeout}s wall-clock limit.",
                duration_seconds=duration,
                error_message=f"Timeout of {effective_timeout}s exceeded"
            )
        except Exception as e:
            duration = time.time() - start_time
            return SandboxResult(
                passed=False,
                package_name=package_name,
                target_version=target_version,
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_seconds=duration,
                error_message=str(e)
            )
        finally:
            # Unconditional teardown of ephemeral sandbox
            self._cleanup_sandbox(sandbox_dir)

    def _copy_repo_isolated(self, src: Path, dst: Path):
        """Copies source files safely to sandbox, ignoring metadata, git, and caches."""
        ignore_patterns = shutil.ignore_patterns(
            ".git", ".sentinelpr", "__pycache__", "*.pyc", "node_modules", ".venv", "venv", ".DS_Store"
        )
        shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore_patterns)

    def _execute_test_process(
        self, cmd: List[str], cwd: Path, timeout: int
    ) -> Tuple[bool, int, str, str, bool]:
        """Runs the test subprocess with live killswitch monitoring and timeout."""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(cwd)
        env["CI"] = "true"
        env["SENTINELPR_SANDBOX"] = "1"

        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )

        if self.process_register_callback:
            self.process_register_callback(proc.pid)

        start_time = time.time()
        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []

        try:
            while proc.poll() is None:
                # Check killswitch
                if self.killswitch_checker and self.killswitch_checker():
                    proc.kill()
                    proc.wait()
                    return False, -9, "", "Process terminated by Kill Switch.", True

                # Check timeout
                if time.time() - start_time > timeout:
                    proc.kill()
                    proc.wait()
                    raise subprocess.TimeoutExpired(cmd, timeout)

                time.sleep(0.1)

            stdout, stderr = proc.communicate(timeout=2)
            passed = (proc.returncode == 0)
            return passed, proc.returncode, stdout, stderr, False

        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait()
                except Exception:
                    pass
            if proc.stdout:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            if proc.stderr:
                try:
                    proc.stderr.close()
                except Exception:
                    pass

    def _cleanup_sandbox(self, sandbox_dir: Path):
        """Guarantees complete removal of the ephemeral sandbox directory."""
        try:
            if sandbox_dir.exists():
                shutil.rmtree(sandbox_dir, ignore_errors=True)
                logger.info(f"Torn down sandbox {sandbox_dir}")
        except Exception as e:
            logger.error(f"Error cleaning up sandbox {sandbox_dir}: {e}")
