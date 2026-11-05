from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

from reconmancer.core.database import connect


SUPPORTED_TOOLS = {
    "httpx",
    "katana",
    "nuclei",
}

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9])v?(\d+\.\d+(?:\.\d+)+(?:[-+][0-9A-Za-z._-]+)?)"
)


def clean_output(value: str) -> str:
    value = ANSI_RE.sub("", value or "")
    return "\n".join(line.strip() for line in value.splitlines() if line.strip())


def load_tool_configuration(home: Path) -> dict:
    path = home / "config" / "tools.yaml"

    if not path.is_file():
        return {}

    try:
        data = yaml.safe_load(
            path.read_text(
                encoding="utf-8",
            )
        )
    except (OSError, yaml.YAMLError):
        return {}

    if not isinstance(data, dict):
        return {}

    tools = data.get(
        "tools",
        {},
    )

    return tools if isinstance(tools, dict) else {}


def configured_tool_path(
    home: Path,
    name: str,
) -> Path | None:
    configuration = load_tool_configuration(home)

    entry = configuration.get(
        name,
        {},
    )

    if not isinstance(entry, dict):
        return None

    value = entry.get("path")

    if not value:
        return None

    return Path(str(value))


def detect_tool_version(
    executable: Path,
) -> str | None:
    """Return a clean semantic version for a ProjectDiscovery binary."""

    commands = [
        [
            str(executable),
            "-version",
            "-nc",
        ],
        [
            str(executable),
            "-version",
        ],
    ]

    for command in commands:
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ):
            continue

        output = clean_output(result.stdout + "\n" + result.stderr)

        if not output:
            continue

        lines = output.splitlines()

        prioritized = [line for line in lines if "version" in line.lower()]

        for line in [
            *prioritized,
            *lines,
        ]:
            match = VERSION_RE.search(line)

            if match:
                return "v" + match.group(1)

    return None


def _project_databases(
    home: Path,
) -> list[Path]:
    projects_root = home / "projects"

    if not projects_root.is_dir():
        return []

    output = []

    for project_root in projects_root.iterdir():
        db_path = project_root / "recon.db"

        if db_path.is_file():
            output.append(db_path)

    return output


def active_engine_jobs(
    home: Path,
    engine: str,
) -> list[dict]:
    active = []

    for db_path in _project_databases(home):
        connection = None

        try:
            connection = connect(db_path)

            table = connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'jobs'
                LIMIT 1
                """
            ).fetchone()

            if table is None:
                continue

            rows = connection.execute(
                """
                SELECT
                    id,
                    status,
                    run_id
                FROM jobs
                WHERE engine = ?
                  AND status IN (
                      'queued',
                      'running'
                  )
                ORDER BY created_at ASC
                """,
                (engine,),
            ).fetchall()

            for row in rows:
                item = dict(row)

                item["project"] = db_path.parent.name

                active.append(item)

        except Exception:
            continue

        finally:
            if connection is not None:
                connection.close()

    return active


def find_pdtm(
    configured_path: Path | None,
) -> Path | None:
    candidates = []

    if configured_path is not None:
        candidates.append(configured_path.parent / "pdtm")

    resolved = shutil.which("pdtm")

    if resolved:
        candidates.append(Path(resolved))

    candidates.append(Path("/root/.pdtm/go/bin/pdtm"))

    seen = set()

    for candidate in candidates:
        key = str(candidate)

        if key in seen:
            continue

        seen.add(key)

        if candidate.is_file() and os.access(
            candidate,
            os.X_OK,
        ):
            return candidate

    return None


def tool_update_capability(
    home: Path,
    name: str,
) -> dict:
    if name not in SUPPORTED_TOOLS:
        return {
            "available": False,
            "reason": "Unsupported tool.",
            "pdtm_path": None,
        }

    path = configured_tool_path(
        home,
        name,
    )

    pdtm = find_pdtm(path)

    if pdtm is None:
        return {
            "available": False,
            "reason": "PDTM was not found.",
            "pdtm_path": None,
        }

    if path is None:
        return {
            "available": False,
            "reason": "Tool path is not configured.",
            "pdtm_path": str(pdtm),
        }

    return {
        "available": True,
        "reason": None,
        "pdtm_path": str(pdtm),
    }


def update_projectdiscovery_tool(
    home: Path,
    name: str,
) -> dict:
    name = name.strip().lower()

    if name not in SUPPORTED_TOOLS:
        raise RuntimeError(f"Unsupported tool: {name}")

    path = configured_tool_path(
        home,
        name,
    )

    if path is None:
        raise RuntimeError(f"No configured path for {name}.")

    active = active_engine_jobs(
        home,
        name,
    )

    if active:
        jobs = ", ".join(f"{item['project']}:{item['id']}" for item in active[:8])

        raise RuntimeError(
            f"Cannot update {name} while a {name} job is queued or running. "
            f"Active job(s): {jobs}"
        )

    pdtm = find_pdtm(path)

    if pdtm is None:
        raise RuntimeError(
            "PDTM was not found. Reconmancer only updates ProjectDiscovery "
            "tools through PDTM so the configured binary path stays consistent."
        )

    before = detect_tool_version(path) if path.is_file() else None

    command = [
        str(pdtm),
        "-bp",
        str(path.parent),
        "-u",
        name,
        "-nc",
        "-duc",
        "-dc",
    ]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{name} update timed out after 10 minutes.") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not run PDTM: {exc}") from exc

    output = clean_output(result.stdout + "\n" + result.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            f"{name} update failed. "
            + (
                output[:1800]
                if output
                else f"PDTM exited with status {result.returncode}."
            )
        )

    if not path.is_file():
        raise RuntimeError(
            f"PDTM completed but the configured {name} binary was not found at {path}."
        )

    after = detect_tool_version(path)

    return {
        "tool": name,
        "before": before or "Unknown",
        "after": after or "Unknown",
        "path": str(path),
        "pdtm": str(pdtm),
        "output": output,
    }
