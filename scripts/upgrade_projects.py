#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from reconmancer.core.analysis import ensure_analysis_schema, refresh_url_analysis
from reconmancer.core.database import migrate_database
from reconmancer.core.findings_workspace import ensure_findings_schema
from reconmancer.core.handoffs import ensure_handoff_schema
from reconmancer.core.jobs import ensure_job_schema, recover_stale_jobs
from reconmancer.core.traffic_evidence import ensure_traffic_evidence_schema
from reconmancer.engines.katana.schema import ensure_katana_schema
from reconmancer.engines.nuclei.schema import ensure_nuclei_schema

HOME = Path("/opt/reconmancer")


def upgrade_project(root: Path) -> dict:
    db = root / "recon.db"
    if not db.is_file():
        return {"slug": root.name, "skipped": True}

    migrate_database(db)
    ensure_job_schema(db)
    ensure_katana_schema(db)
    ensure_nuclei_schema(db)
    ensure_handoff_schema(db)
    ensure_findings_schema(db)
    ensure_traffic_evidence_schema(db)
    ensure_analysis_schema(db)
    analysis = refresh_url_analysis(db, batch_size=1000, max_batches=10000)
    recovery = recover_stale_jobs(db)
    return {
        "slug": root.name,
        "skipped": False,
        "analysis": analysis,
        "recovery": recovery,
    }


def main() -> None:
    projects = HOME / "projects"
    if not projects.is_dir():
        print("No projects directory found; schema migration skipped.")
        return

    upgraded = 0
    for root in sorted(projects.iterdir()):
        if not root.is_dir():
            continue
        try:
            result = upgrade_project(root)
        except Exception as exc:
            print(f"[FAIL] {root.name}: {exc}")
            raise
        if result["skipped"]:
            continue
        upgraded += 1
        analysis = result["analysis"]
        recovery = result["recovery"]
        print(
            f"[OK] {root.name}: "
            f"analyzed {analysis['processed_urls']} URL(s), "
            f"recovered {recovery['interrupted']} interrupted job(s)"
        )

    print(f"Reconmancer upgrade complete: {upgraded} project(s) migrated.")


if __name__ == "__main__":
    main()
