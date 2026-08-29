"""
SentinelPR - Sandbox Resource Limits & Safety Policy Configuration
"""

from dataclasses import dataclass
import os
import resource
from typing import Callable, Optional

MAX_MEMORY_LIMIT_BYTES = 512 * 1024 * 1024  # 512 MB
MAX_CPU_TIME_LIMIT_SECS = 180  # 180 seconds
MAX_MEMORY_LIMIT = "512m"
MAX_CPU_LIMIT = "1.0"
DEFAULT_TIMEOUT = 180


@dataclass
class SandboxResourcePolicy:
    """Encapsulates memory and CPU limits for sandbox executions."""
    max_memory_bytes: int = MAX_MEMORY_LIMIT_BYTES
    max_cpu_seconds: int = MAX_CPU_TIME_LIMIT_SECS
    docker_memory: str = MAX_MEMORY_LIMIT
    docker_cpus: str = MAX_CPU_LIMIT

    def get_preexec_fn(self) -> Optional[Callable[[], None]]:
        """Returns a preexec function to enforce OS-level resource limits on POSIX."""
        def set_limits():
            try:
                # Set Address Space (Virtual Memory) limit
                resource.setrlimit(resource.RLIMIT_AS, (self.max_memory_bytes, self.max_memory_bytes))
            except (ValueError, OSError):
                pass
            try:
                # Set CPU Time limit
                resource.setrlimit(resource.RLIMIT_CPU, (self.max_cpu_seconds, self.max_cpu_seconds + 5))
            except (ValueError, OSError):
                pass
        return set_limits
