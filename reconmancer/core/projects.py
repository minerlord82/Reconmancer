from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from reconmancer.core.database import initialize_database


PROJECT_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_slug(slug: str) -> None:

    if not PROJECT_SLUG_PATTERN.fullmatch(slug):
        raise ValueError(
            "Project slug may only contain letters, numbers, '.', '_' and '-'."
        )


def project_path(
    home: Path,
    slug: str,
) -> Path:

    validate_slug(slug)

    return home / "projects" / slug


def create_project(
    home: Path,
    name: str,
    slug: str,
    disk_limit_gb: float = 10.0,
) -> Path:

    validate_slug(slug)

    root = project_path(
        home,
        slug,
    )

    if root.exists():
        raise FileExistsError(f"Project already exists: {slug}")

    directories = [
        "input",
        "raw/httpx",
        "raw/katana",
        "raw/nuclei",
        "objects/screenshots",
        "objects/thumbnails",
        "objects/responses",
        "objects/evidence",
        "secrets/auth",
        "logs",
        "temp",
    ]

    root.mkdir(
        parents=True,
        exist_ok=False,
    )

    for directory in directories:
        (root / directory).mkdir(
            parents=True,
            exist_ok=True,
        )

    config = {
        "project": {
            "name": name,
            "slug": slug,
            "created_at": now_iso(),
        },
        "resources": {
            "disk_limit_gb": disk_limit_gb,
        },
        "defaults": {
            "authentication": "anonymous",
        },
        "maintenance": {
            "compression": {
                "enabled": False,
                "algorithm": "zstd",
                "minimum_age_days": 7.0,
                "minimum_size_mb": 1.0,
                "max_files_per_pass": 50,
            },
        },
        "engines": {
            "httpx": {
                "enabled": True,
            },
            "katana": {
                "enabled": True,
            },
            "nuclei": {
                "enabled": True,
            },
        },
    }

    with (root / "project.yaml").open(
        "w",
        encoding="utf-8",
    ) as handle:
        yaml.safe_dump(
            config,
            handle,
            sort_keys=False,
        )

    (root / "input" / "targets.txt").touch()

    initialize_database(root / "recon.db")

    return root


def load_project(
    home: Path,
    slug: str,
) -> dict:

    root = project_path(
        home,
        slug,
    )

    config_file = root / "project.yaml"

    if not config_file.exists():
        raise FileNotFoundError(f"Unknown project: {slug}")

    with config_file.open(
        "r",
        encoding="utf-8",
    ) as handle:
        config = yaml.safe_load(handle)

    return {
        "root": root,
        "config": config,
        "database": root / "recon.db",
    }


def list_projects(
    home: Path,
) -> list[dict]:

    projects_root = home / "projects"

    if not projects_root.exists():
        return []

    results = []

    for child in sorted(projects_root.iterdir()):
        if not child.is_dir():
            continue

        config_file = child / "project.yaml"

        if not config_file.exists():
            continue

        try:
            with config_file.open(
                "r",
                encoding="utf-8",
            ) as handle:
                config = yaml.safe_load(handle)

            results.append(
                {
                    "slug": child.name,
                    "name": config["project"]["name"],
                    "root": child,
                }
            )

        except Exception:
            continue

    return results


def directory_size(path: Path) -> int:

    total = 0

    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size

        except OSError:
            continue

    return total
