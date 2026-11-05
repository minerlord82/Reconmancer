from __future__ import annotations

from pathlib import Path
import subprocess

import yaml


HOME = Path("/opt/reconmancer")

TOOLS_CONFIG = HOME / "config" / "tools.yaml"


def load_tools() -> dict:

    with TOOLS_CONFIG.open(
        "r",
        encoding="utf-8",
    ) as handle:
        config = yaml.safe_load(handle)

    return config.get(
        "tools",
        {},
    )


def get_tool_path(name: str) -> Path:

    tools = load_tools()

    if name not in tools:
        raise KeyError(f"Unknown tool: {name}")

    raw_path = tools[name].get("path")

    if not raw_path:
        raise RuntimeError(f"No path configured for {name}")

    path = Path(raw_path)

    if not path.exists():
        raise FileNotFoundError(f"{name} executable not found: {path}")

    if not path.is_file():
        raise RuntimeError(f"{name} path is not a file: {path}")

    return path


def get_tool_version(
    name: str,
) -> str:

    path = get_tool_path(name)

    process = subprocess.run(
        [
            str(path),
            "-version",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )

    output = (process.stdout + "\n" + process.stderr).strip()

    return output
