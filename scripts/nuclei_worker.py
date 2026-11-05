#!/usr/bin/env python3

from __future__ import annotations

import argparse
import traceback
from pathlib import Path

from reconmancer.core.jobs import (
    JobHeartbeat,
    attach_job_run,
    set_job_completed,
    set_job_failed,
    set_job_interrupted,
    set_job_running,
)
from reconmancer.core.projects import load_project
from reconmancer.core.scan_watchdog import ScanInterruptedError
from reconmancer.core.worker_maintenance import post_scan_maintenance
from reconmancer.engines.nuclei.runner import run_nuclei


HOME = Path("/opt/reconmancer")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("project")
    parser.add_argument("job_id")
    parser.add_argument("target_file")
    parser.add_argument("--severity", action="append", default=[])
    parser.add_argument("--tags", default="")
    parser.add_argument("--exclude-tags", default="dos,fuzz,bruteforce")
    parser.add_argument("--rate-limit", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--bulk-size", type=int, default=5)
    parser.add_argument("--no-interactsh", action="store_true")
    parser.add_argument("--allow-headless", action="store_true")
    parser.add_argument(
        "--template-source",
        choices=["default", "projectdiscovery"],
        default="default",
    )
    parser.add_argument("--auth-profile-id", default=None)
    args = parser.parse_args()

    project = load_project(HOME, args.project)
    db_path = project["database"]

    try:
        set_job_running(db_path, args.job_id)

        with JobHeartbeat(db_path, args.job_id):

            def on_run_started(run_id: str) -> None:
                attach_job_run(db_path, args.job_id, run_id)

            run_id = run_nuclei(
                args.project,
                target_file=Path(args.target_file),
                severities=args.severity,
                tags=args.tags,
                exclude_tags=args.exclude_tags,
                rate_limit=args.rate_limit,
                concurrency=args.concurrency,
                bulk_size=args.bulk_size,
                no_interactsh=args.no_interactsh,
                allow_headless=args.allow_headless,
                template_source=args.template_source,
                auth_profile_id=args.auth_profile_id,
                on_run_started=on_run_started,
            )

            maintenance = post_scan_maintenance(project, current_job_id=args.job_id)
            print("Post-scan maintenance:", maintenance)

        set_job_completed(db_path, args.job_id, run_id=run_id)
        print(f"Job {args.job_id} completed as {run_id}")

    except ScanInterruptedError as exc:
        set_job_interrupted(db_path, args.job_id, str(exc))
        print(f"Job {args.job_id} interrupted: {exc}")

    except Exception as exc:
        set_job_failed(db_path, args.job_id, str(exc))
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
