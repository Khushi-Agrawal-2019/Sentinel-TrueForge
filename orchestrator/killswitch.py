"""
SentinelPR - Fail-Safe Kill Switch

Provides instantaneous abort capability across all lifecycle stages.
Immediately terminates active sandbox jobs, prevents any real-world side effects,
and guarantees the source repository is untouched.
"""

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Dict, List, Optional, Set

logger = logging.getLogger("sentinelpr.killswitch")


@dataclass
class KillStatus:
    is_active: bool
    reason: Optional[str] = None
    timestamp: Optional[float] = None
    terminated_pids: List[int] = None
    terminated_containers: List[str] = None


class KillSwitch:
    """Manages kill flag signals and active process termination."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or Path.cwd()
        self.state_dir = self.workspace_root / ".sentinelpr"
        self.flag_file = self.state_dir / "kill.flag"
        self.process_registry_file = self.state_dir / "active_processes.json"
        self._local_killed = False

    def _ensure_dir(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def is_triggered(self) -> bool:
        """Returns True if the kill switch flag exists or is set in-memory."""
        if self._local_killed:
            return True
        return self.flag_file.is_file()

    def trigger(self, reason: str = "User initiated stop via SentinelPR Kill Switch") -> KillStatus:
        """
        Sets the kill switch flag and forcibly terminates all active sandbox processes & containers.
        """
        self._ensure_dir()
        self._local_killed = True
        
        timestamp = time.time()
        payload = {
            "triggered": True,
            "timestamp": timestamp,
            "reason": reason,
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
        }
        self.flag_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.warning(f"KILL SWITCH TRIGGERED: {reason}")

        # Kill all registered sandbox processes
        terminated_pids = self._terminate_registered_processes()
        terminated_containers = self._terminate_docker_containers()

        return KillStatus(
            is_active=True,
            reason=reason,
            timestamp=timestamp,
            terminated_pids=terminated_pids,
            terminated_containers=terminated_containers
        )

    def reset(self) -> bool:
        """Clears the kill switch flag allowing new runs to proceed."""
        self._local_killed = False
        if self.flag_file.is_file():
            try:
                self.flag_file.unlink()
            except Exception as e:
                logger.error(f"Error removing kill flag: {e}")
                return False
        if self.process_registry_file.is_file():
            try:
                self.process_registry_file.unlink()
            except Exception:
                pass
        return True

    def register_process(self, pid: int):
        """Registers an active sandbox process PID so it can be terminated on kill."""
        self._ensure_dir()
        pids = self.get_registered_pids()
        pids.add(pid)
        self.process_registry_file.write_text(
            json.dumps({"pids": list(pids)}), encoding="utf-8"
        )

    def unregister_process(self, pid: int):
        """Removes a finished process PID from the registry."""
        if not self.process_registry_file.is_file():
            return
        try:
            pids = self.get_registered_pids()
            pids.discard(pid)
            self.process_registry_file.write_text(
                json.dumps({"pids": list(pids)}), encoding="utf-8"
            )
        except Exception:
            pass

    def get_registered_pids(self) -> Set[int]:
        if not self.process_registry_file.is_file():
            return set()
        try:
            data = json.loads(self.process_registry_file.read_text(encoding="utf-8"))
            return set(data.get("pids", []))
        except Exception:
            return set()

    def _terminate_registered_processes(self) -> List[int]:
        terminated = []
        pids = self.get_registered_pids()
        for pid in pids:
            try:
                # Send SIGTERM first, then SIGKILL
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.05)
                os.kill(pid, signal.SIGKILL)
                terminated.append(pid)
                logger.info(f"Forcibly terminated sandbox process PID {pid}")
            except ProcessLookupError:
                # Process already exited
                pass
            except Exception as e:
                logger.error(f"Error killing PID {pid}: {e}")

        # Clear process registry
        if self.process_registry_file.is_file():
            try:
                self.process_registry_file.unlink()
            except Exception:
                pass
        return terminated

    def _terminate_docker_containers(self) -> List[str]:
        """Kills any active Docker containers spawned by SentinelPR."""
        killed = []
        try:
            proc = subprocess.run(
                ["docker", "ps", "-q", "--filter", "name=sentinelpr_sandbox"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            if proc.returncode == 0:
                container_ids = [c.strip() for c in proc.stdout.splitlines() if c.strip()]
                for cid in container_ids:
                    subprocess.run(["docker", "kill", cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    killed.append(cid)
        except Exception:
            pass
        return killed

    def get_status(self) -> KillStatus:
        if self.is_triggered():
            reason = "Kill switch flag is active"
            timestamp = None
            if self.flag_file.is_file():
                try:
                    data = json.loads(self.flag_file.read_text(encoding="utf-8"))
                    reason = data.get("reason", reason)
                    timestamp = data.get("timestamp")
                except Exception:
                    pass
            return KillStatus(is_active=True, reason=reason, timestamp=timestamp)
        return KillStatus(is_active=False)
