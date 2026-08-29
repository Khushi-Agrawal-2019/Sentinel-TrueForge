"""
SentinelPR - Manifest Parser & Version Updater

Detects and parses dependency manifests (requirements.txt, package.json, pyproject.toml)
and provides safe in-place version bumping for sandboxed execution.
"""

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple


@dataclass
class ManifestDependency:
    name: str
    version: Optional[str]
    ecosystem: str
    manifest_path: Path
    raw_spec: str


class ManifestParser:
    """Parses repository manifests to identify pinned dependencies."""

    @staticmethod
    def detect_manifests(repo_dir: Path) -> List[Path]:
        """Finds supported dependency manifests in the repository root or immediate subdirs."""
        candidates = [
            "requirements.txt",
            "package.json",
            "pyproject.toml",
            "Pipfile"
        ]
        found = []
        for cand in candidates:
            p = repo_dir / cand
            if p.is_file():
                found.append(p)
        return found

    @classmethod
    def parse_repository(cls, repo_dir: Path) -> List[ManifestDependency]:
        """Scans and extracts all dependencies across detected manifests."""
        manifests = cls.detect_manifests(repo_dir)
        deps: List[ManifestDependency] = []
        for m in manifests:
            if m.name == "requirements.txt":
                deps.extend(cls.parse_requirements_txt(m))
            elif m.name == "package.json":
                deps.extend(cls.parse_package_json(m))
            elif m.name == "pyproject.toml":
                deps.extend(cls.parse_pyproject_toml(m))
        return deps

    @staticmethod
    def parse_requirements_txt(path: Path) -> List[ManifestDependency]:
        """Parses a Python requirements.txt file."""
        deps = []
        if not path.is_file():
            return deps

        content = path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Match patterns like jinja2==2.11.2, requests>=2.25.1, etc.
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:(==|>=|<=|~=|!=)\s*([a-zA-Z0-9_\-\.]+))?", line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(3) if match.group(3) else None
                deps.append(
                    ManifestDependency(
                        name=pkg_name,
                        version=version,
                        ecosystem="PyPI",
                        manifest_path=path,
                        raw_spec=line
                    )
                )
        return deps

    @staticmethod
    def parse_package_json(path: Path) -> List[ManifestDependency]:
        """Parses a Node.js package.json file."""
        deps = []
        if not path.is_file():
            return deps

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for section in ["dependencies", "devDependencies"]:
                for name, spec in data.get(section, {}).items():
                    # Clean semver prefix (^, ~, >=, etc.) for OSV query
                    clean_version = re.sub(r"^[^\d]*", "", str(spec)).strip()
                    deps.append(
                        ManifestDependency(
                            name=name,
                            version=clean_version if clean_version else None,
                            ecosystem="npm",
                            manifest_path=path,
                            raw_spec=str(spec)
                        )
                    )
        except Exception:
            pass
        return deps

    @staticmethod
    def parse_pyproject_toml(path: Path) -> List[ManifestDependency]:
        """Simple regex parser for pyproject.toml dependencies."""
        deps = []
        if not path.is_file():
            return deps

        content = path.read_text(encoding="utf-8")
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if "dependencies" in line and "[" in line:
                in_deps = True
                continue
            if in_deps:
                if line.endswith("]"):
                    in_deps = False
                    continue
                clean_line = line.strip('"\' ,')
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:(==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+))?", clean_line)
                if match:
                    deps.append(
                        ManifestDependency(
                            name=match.group(1).lower(),
                            version=match.group(3) if match.group(3) else None,
                            ecosystem="PyPI",
                            manifest_path=path,
                            raw_spec=clean_line
                        )
                    )
        return deps

    @classmethod
    def apply_version_bump(cls, manifest_path: Path, package_name: str, new_version: str) -> bool:
        """
        Safely applies a dependency version bump to a manifest inside the sandbox.
        Returns True if successful.
        """
        if not manifest_path.is_file():
            return False

        if manifest_path.name == "requirements.txt":
            return cls._bump_requirements_txt(manifest_path, package_name, new_version)
        elif manifest_path.name == "package.json":
            return cls._bump_package_json(manifest_path, package_name, new_version)
        return False

    @staticmethod
    def _bump_requirements_txt(path: Path, package_name: str, new_version: str) -> bool:
        content = path.read_text(encoding="utf-8")
        lines = content.splitlines()
        updated = False
        new_lines = []

        pattern = re.compile(rf"^{re.escape(package_name)}\s*(==|>=|<=|~=|!=)?.*$", re.IGNORECASE)
        for line in lines:
            if pattern.match(line.strip()):
                new_lines.append(f"{package_name}=={new_version}")
                updated = True
            else:
                new_lines.append(line)

        if updated:
            path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return updated

    @staticmethod
    def _bump_package_json(path: Path, package_name: str, new_version: str) -> bool:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            updated = False
            for section in ["dependencies", "devDependencies"]:
                if section in data and package_name in data[section]:
                    data[section][package_name] = new_version
                    updated = True
            if updated:
                path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            return updated
        except Exception:
            return False
