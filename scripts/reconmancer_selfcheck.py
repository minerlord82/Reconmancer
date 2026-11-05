#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

from reconmancer.core.analysis import ensure_analysis_schema
from reconmancer.core.findings_workspace import ensure_findings_schema
from reconmancer.core.handoffs import ensure_handoff_schema
from reconmancer.core.jobs import ensure_job_schema
from reconmancer.core.traffic_evidence import ensure_traffic_evidence_schema
from reconmancer.engines.katana.schema import ensure_katana_schema
from reconmancer.engines.nuclei.schema import ensure_nuclei_schema

HOME = Path("/opt/reconmancer")


def tool_paths() -> dict[str, Path]:
    path = HOME / "config" / "tools.yaml"
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tools = data.get("tools", {}) or {}
    output = {}
    for name, entry in tools.items():
        if isinstance(entry, dict) and entry.get("path"):
            output[name] = Path(entry["path"])
    return output


def help_text(path: Path) -> str:
    result = subprocess.run(
        [str(path), "-h"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
        check=False,
    )
    return result.stdout


def check_tools() -> list[str]:
    warnings = []
    required = {
        "httpx": ["-irr", "-sf", "-system-chrome", "-ho"],
        "katana": ["-hl", "-ho", "-cdd", "-noi", "-fs"],
        "nuclei": ["-irr", "-sf", "-headless", "-ho"],
    }
    paths = tool_paths()
    for name, flags in required.items():
        path = paths.get(name)
        if not path or not path.is_file():
            warnings.append(f"{name}: configured binary missing")
            continue
        try:
            text = help_text(path)
        except Exception as exc:
            warnings.append(f"{name}: could not read help: {exc}")
            continue
        missing = [flag for flag in flags if flag not in text]
        if missing:
            warnings.append(f"{name}: missing expected flags: {', '.join(missing)}")
        else:
            print(f"[OK] {name}: required evidence/auth flags present")

    if not any(
        shutil.which(name)
        for name in (
            "chromium",
            "chromium-browser",
            "google-chrome",
            "google-chrome-stable",
        )
    ):
        warnings.append(
            "No system Chromium/Chrome found; authenticated browser/headless features need one installed."
        )
    else:
        print("[OK] system Chrome/Chromium found")

    if shutil.which("zstd"):
        print("[OK] zstd available")
    else:
        print(
            "[INFO] zstd not installed; choose gzip in Settings or leave compression disabled"
        )

    return warnings


def check_projects() -> None:
    projects = HOME / "projects"
    if not projects.is_dir():
        return
    for root in sorted(projects.iterdir()):
        db = root / "recon.db"
        if not db.is_file():
            continue
        ensure_job_schema(db)
        ensure_katana_schema(db)
        ensure_nuclei_schema(db)
        ensure_handoff_schema(db)
        ensure_findings_schema(db)
        ensure_traffic_evidence_schema(db)
        ensure_analysis_schema(db)
        print(f"[OK] {root.name}: required schemas available")


def main() -> None:
    warnings = check_tools()
    check_projects()
    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"  - {warning}")
    print("\nReconmancer self-check complete.")


if __name__ == "__main__":
    main()
