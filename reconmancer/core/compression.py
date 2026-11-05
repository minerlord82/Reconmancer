from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


COMPRESSIBLE_SUFFIXES = {
    ".jsonl",
    ".log",
    ".txt",
    ".json",
}


def now_timestamp() -> float:
    return datetime.now(timezone.utc).timestamp()


def zstd_available() -> bool:
    return shutil.which("zstd") is not None


def compression_capabilities() -> dict:
    return {
        "zstd": zstd_available(),
        "gzip": True,
    }


def _eligible(
    path: Path,
    *,
    minimum_age_seconds: float,
    minimum_size_bytes: int,
) -> bool:
    if not path.is_file():
        return False

    if path.suffix in {".zst", ".gz"}:
        return False

    if path.suffix.lower() not in COMPRESSIBLE_SUFFIXES:
        return False

    if path.name in {"command.txt"}:
        return False

    stat = path.stat()

    if stat.st_size < minimum_size_bytes:
        return False

    age = now_timestamp() - stat.st_mtime
    return age >= minimum_age_seconds


def _compress_zstd(path: Path) -> Path:
    executable = shutil.which("zstd")
    if not executable:
        raise RuntimeError(
            "zstd compression is enabled, but the zstd executable is not installed."
        )

    destination = path.with_name(path.name + ".zst")
    temporary = destination.with_name(destination.name + ".tmp")

    subprocess.run(
        [
            executable,
            "-q",
            "-T1",
            "-3",
            "-f",
            str(path),
            "-o",
            str(temporary),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    temporary.replace(destination)
    path.unlink()
    return destination


def _compress_gzip(path: Path) -> Path:
    destination = path.with_name(path.name + ".gz")
    destination.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    os.close(fd)
    temporary = Path(temp_name)

    try:
        with (
            path.open("rb") as source,
            gzip.open(temporary, "wb", compresslevel=6) as target,
        ):
            shutil.copyfileobj(source, target, length=1024 * 1024)

        temporary.replace(destination)
        path.unlink()
        return destination
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def compress_eligible_project(
    project_root: Path,
    *,
    enabled: bool,
    algorithm: str = "zstd",
    minimum_age_days: float = 7.0,
    minimum_size_mb: float = 1.0,
    max_files: int = 100,
    exclude_paths: set[Path] | None = None,
) -> dict:
    summary = {
        "enabled": bool(enabled),
        "algorithm": algorithm,
        "scanned": 0,
        "compressed": 0,
        "before_bytes": 0,
        "after_bytes": 0,
        "saved_bytes": 0,
        "errors": [],
    }

    if not enabled:
        return summary

    if algorithm not in {"zstd", "gzip"}:
        raise ValueError("Unsupported compression algorithm.")

    if algorithm == "zstd" and not zstd_available():
        summary["errors"].append(
            "zstd executable is not installed; no files were compressed."
        )
        return summary

    roots = [
        project_root / "raw",
        project_root / "logs" / "jobs",
    ]

    minimum_age_seconds = max(0.0, float(minimum_age_days)) * 86400.0
    minimum_size_bytes = max(0, int(float(minimum_size_mb) * 1024 * 1024))

    candidates: list[Path] = []
    excluded = {path.resolve() for path in (exclude_paths or set())}

    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            summary["scanned"] += 1
            try:
                if path.resolve() in excluded:
                    continue
                if _eligible(
                    path,
                    minimum_age_seconds=minimum_age_seconds,
                    minimum_size_bytes=minimum_size_bytes,
                ):
                    candidates.append(path)
            except OSError:
                continue

    candidates.sort(key=lambda item: item.stat().st_mtime)

    for path in candidates[: max(1, int(max_files))]:
        try:
            before = path.stat().st_size
            if algorithm == "zstd":
                destination = _compress_zstd(path)
            else:
                destination = _compress_gzip(path)
            after = destination.stat().st_size

            summary["compressed"] += 1
            summary["before_bytes"] += before
            summary["after_bytes"] += after
            summary["saved_bytes"] += max(0, before - after)
        except Exception as exc:
            summary["errors"].append(f"{path}: {exc}")

    return summary


def compression_settings_from_project(project: dict) -> dict:
    config = project.get("config", {}) or {}
    maintenance = config.get("maintenance", {}) or {}
    compression = maintenance.get("compression", {}) or {}

    return {
        "enabled": bool(compression.get("enabled", False)),
        "algorithm": str(compression.get("algorithm", "zstd")),
        "minimum_age_days": float(compression.get("minimum_age_days", 7.0)),
        "minimum_size_mb": float(compression.get("minimum_size_mb", 1.0)),
        "max_files_per_pass": int(compression.get("max_files_per_pass", 50)),
    }


def maybe_run_compression(
    project: dict,
    *,
    exclude_paths: set[Path] | None = None,
) -> dict:
    settings = compression_settings_from_project(project)
    return compress_eligible_project(
        project["root"],
        enabled=settings["enabled"],
        algorithm=settings["algorithm"],
        minimum_age_days=settings["minimum_age_days"],
        minimum_size_mb=settings["minimum_size_mb"],
        max_files=settings["max_files_per_pass"],
        exclude_paths=exclude_paths,
    )
