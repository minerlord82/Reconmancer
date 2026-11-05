from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

from reconmancer.core.compression import compression_capabilities
from reconmancer.core.nuclei_templates import (
    projectdiscovery_template_status,
)
from reconmancer.core.tool_updates import (
    detect_tool_version,
    tool_update_capability,
)


DEFAULT_SCAN_SETTINGS = {
    "httpx": {
        "rate_limit": 10,
        "redirect_depth": 10,
        "screenshots": False,
    },
    "katana": {
        "profile": "standard",
        "depth": 3,
        "rate_limit": 20,
        "concurrency": 5,
        "parallelism": 2,
        "page_load_strategy": "heuristic",
        "js_crawl": True,
        "known_files": True,
        "form_extraction": True,
        "tech_detect": True,
        "no_scope": False,
    },
    "nuclei": {
        "severities": ["info", "low", "medium", "high", "critical"],
        "tags": "",
        "exclude_tags": "dos,fuzz,bruteforce",
        "rate_limit": 10,
        "concurrency": 5,
        "bulk_size": 5,
        "no_interactsh": True,
        "allow_headless": False,
    },
}

DEFAULT_COMPRESSION_SETTINGS = {
    "enabled": False,
    "algorithm": "zstd",
    "minimum_age_days": 7.0,
    "minimum_size_mb": 1.0,
    "max_files_per_pass": 50,
}

VALID_KATANA_PROFILES = {"standard", "headless", "deep"}
VALID_PAGE_LOAD_STRATEGIES = {
    "heuristic",
    "load",
    "domcontentloaded",
    "networkidle",
    "none",
}
VALID_NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
VALID_COMPRESSION_ALGORITHMS = {"zstd", "gzip"}


def deep_merge(base: dict, override: dict) -> dict:
    output = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(output.get(key), dict):
            output[key] = deep_merge(output[key], value)
        else:
            output[key] = copy.deepcopy(value)
    return output


def atomic_write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            data,
            handle,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def get_project_settings(project: dict) -> dict:
    config = project["config"]
    resources = config.get("resources", {}) or {}
    defaults = config.get("defaults", {}) or {}
    maintenance = config.get("maintenance", {}) or {}

    scan = deep_merge(
        DEFAULT_SCAN_SETTINGS,
        {
            "httpx": defaults.get("httpx", {}) or {},
            "katana": defaults.get("katana", {}) or {},
            "nuclei": defaults.get("nuclei", {}) or {},
        },
    )

    compression = deep_merge(
        DEFAULT_COMPRESSION_SETTINGS,
        maintenance.get("compression", {}) or {},
    )

    if compression["algorithm"] not in VALID_COMPRESSION_ALGORITHMS:
        compression["algorithm"] = "zstd"

    return {
        "disk_limit_gb": float(resources.get("disk_limit_gb", 10.0)),
        "authentication": defaults.get("authentication", "anonymous"),
        "httpx": scan["httpx"],
        "katana": scan["katana"],
        "nuclei": scan["nuclei"],
        "compression": compression,
    }


def save_project_settings(project: dict, settings: dict) -> None:
    config = copy.deepcopy(project["config"])
    resources = config.setdefault("resources", {})
    defaults = config.setdefault("defaults", {})
    maintenance = config.setdefault("maintenance", {})

    resources["disk_limit_gb"] = float(settings["disk_limit_gb"])
    defaults.setdefault("authentication", "anonymous")
    defaults["httpx"] = copy.deepcopy(settings["httpx"])
    defaults["katana"] = copy.deepcopy(settings["katana"])
    defaults["nuclei"] = copy.deepcopy(settings["nuclei"])
    maintenance["compression"] = copy.deepcopy(settings["compression"])

    atomic_write_yaml(project["root"] / "project.yaml", config)


def load_tool_configuration(home: Path) -> dict:
    path = home / "config" / "tools.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(data, dict):
        return {}
    tools = data.get("tools", {})
    return tools if isinstance(tools, dict) else {}


def tool_statuses(home: Path) -> list[dict]:
    configuration = load_tool_configuration(home)
    output = []

    for name in (
        "httpx",
        "katana",
        "nuclei",
    ):
        entry = configuration.get(
            name,
            {},
        )

        if not isinstance(
            entry,
            dict,
        ):
            entry = {}

        configured_path = entry.get("path")

        path = Path(configured_path) if configured_path else None

        exists = bool(path and path.is_file())

        executable = bool(
            exists
            and os.access(
                path,
                os.X_OK,
            )
        )

        version = detect_tool_version(path) if executable else None

        update = tool_update_capability(
            home,
            name,
        )

        output.append(
            {
                "name": name,
                "path": (str(path) if path else "Not configured"),
                "exists": exists,
                "executable": executable,
                "version": version or "Unknown",
                "can_update": bool(update.get("available") and executable),
                "update_reason": update.get("reason"),
                "updater": ("PDTM" if update.get("available") else "Unavailable"),
            }
        )

    return output


def build_settings_workspace(home: Path, project: dict) -> dict:
    return {
        "settings": get_project_settings(project),
        "tools": tool_statuses(home),
        "compression_capabilities": compression_capabilities(),
        "nuclei_templates": projectdiscovery_template_status(home),
    }
