from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from reconmancer.core.jobs import (
    create_job,
    get_job,
    set_job_failed,
    set_job_target_file,
)


HOME = Path("/opt/reconmancer")


def write_job_targets(
    project: dict,
    job_id: str,
    targets: list[str],
) -> Path:
    directory = project["root"] / "input" / "jobs" / job_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "targets.txt"
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return path


def resolve_target_file(
    project: dict,
    job_id: str,
    *,
    targets: list[str] | None,
    target_file: Path | str | None,
    copy_external: bool = False,
) -> Path:
    if target_file is not None:
        source = Path(target_file)
        if not source.is_file():
            raise ValueError("Job target file does not exist.")

        if copy_external:
            destination = project["root"] / "input" / "jobs" / job_id / "targets.txt"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            return destination

        return source

    if not targets:
        raise ValueError("Job has no targets.")

    clean: list[str] = []
    seen = set()
    for target in targets:
        value = str(target).replace("\r", "").replace("\n", "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        clean.append(value)

    if not clean:
        raise ValueError("Job target list is empty after normalization.")

    return write_job_targets(project, job_id, clean)


def spawn_job(
    project: dict,
    job_id: str,
    command: list[str],
) -> None:
    log_directory = project["root"] / "logs" / "jobs"
    log_directory.mkdir(parents=True, exist_ok=True)
    log_path = log_directory / f"{job_id}.log"

    try:
        with log_path.open("a", encoding="utf-8") as log_handle:
            subprocess.Popen(
                command,
                cwd=str(HOME),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
    except Exception as exc:
        set_job_failed(project["database"], job_id, str(exc))
        raise


def _httpx_command(
    project: dict,
    job_id: str,
    target_file: Path,
    payload: dict,
    auth_profile_id: str | None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "scripts.httpx_worker",
        project["config"]["project"]["slug"],
        job_id,
        str(target_file),
        "--rate-limit",
        str(payload.get("rate_limit", 10)),
        "--redirect-depth",
        str(payload.get("redirect_depth", 10)),
    ]

    if payload.get("screenshots", False):
        command.append("--screenshots")

    if auth_profile_id:
        command.extend(["--auth-profile-id", auth_profile_id])

    return command


def _katana_command(
    project: dict,
    job_id: str,
    target_file: Path,
    payload: dict,
    auth_profile_id: str | None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "scripts.katana_worker",
        project["config"]["project"]["slug"],
        job_id,
        str(target_file),
        "--profile",
        str(payload.get("profile", "standard")),
        "--depth",
        str(payload.get("depth", 3)),
        "--rate-limit",
        str(payload.get("rate_limit", 20)),
        "--concurrency",
        str(payload.get("concurrency", 5)),
        "--parallelism",
        str(payload.get("parallelism", 2)),
        "--page-load-strategy",
        str(payload.get("page_load_strategy", "heuristic")),
    ]

    for payload_key, flag in (
        ("js_crawl", "--js-crawl"),
        ("known_files", "--known-files"),
        ("form_extraction", "--form-extraction"),
        ("tech_detect", "--tech-detect"),
        ("no_scope", "--no-scope"),
    ):
        if payload.get(payload_key, False):
            command.append(flag)

    if auth_profile_id:
        command.extend(["--auth-profile-id", auth_profile_id])

    return command


def _nuclei_command(
    project: dict,
    job_id: str,
    target_file: Path,
    payload: dict,
    auth_profile_id: str | None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "scripts.nuclei_worker",
        project["config"]["project"]["slug"],
        job_id,
        str(target_file),
        "--tags",
        str(payload.get("tags", "")),
        "--exclude-tags",
        str(payload.get("exclude_tags", "dos,fuzz,bruteforce")),
        "--rate-limit",
        str(payload.get("rate_limit", 10)),
        "--concurrency",
        str(payload.get("concurrency", 5)),
        "--bulk-size",
        str(payload.get("bulk_size", 5)),
        "--template-source",
        str(
            payload.get("template_source")
            or (
                "projectdiscovery"
                if payload.get("template_mode") == "new"
                else "default"
            )
        ),
    ]

    for severity in payload.get("severities", []):
        command.extend(["--severity", str(severity)])

    if payload.get("no_interactsh", True):
        command.append("--no-interactsh")

    if payload.get("allow_headless", False):
        command.append("--allow-headless")

    if auth_profile_id:
        command.extend(["--auth-profile-id", auth_profile_id])

    return command


def dispatch_scan_job(
    project: dict,
    *,
    engine: str,
    payload: dict,
    targets: list[str] | None = None,
    target_file: Path | str | None = None,
    auth_profile_id: str | None = None,
    retry_of: str | None = None,
    copy_target_file: bool = False,
) -> str:
    if engine not in {"httpx", "katana", "nuclei"}:
        raise ValueError(f"Unsupported engine: {engine}")

    safe_payload = dict(payload)

    if auth_profile_id:
        safe_payload["auth_profile_id"] = auth_profile_id
        safe_payload["context"] = f"auth:{auth_profile_id}"
    else:
        safe_payload.pop("auth_profile_id", None)
        safe_payload.setdefault("context", "anonymous")

    job_id = create_job(
        project["database"],
        engine=engine,
        payload=safe_payload,
        retry_of=retry_of,
    )

    try:
        resolved_target_file = resolve_target_file(
            project,
            job_id,
            targets=targets,
            target_file=target_file,
            copy_external=copy_target_file,
        )

        set_job_target_file(
            project["database"],
            job_id,
            resolved_target_file,
        )

        if engine == "httpx":
            command = _httpx_command(
                project,
                job_id,
                resolved_target_file,
                safe_payload,
                auth_profile_id,
            )
        elif engine == "katana":
            command = _katana_command(
                project,
                job_id,
                resolved_target_file,
                safe_payload,
                auth_profile_id,
            )
        else:
            command = _nuclei_command(
                project,
                job_id,
                resolved_target_file,
                safe_payload,
                auth_profile_id,
            )

        spawn_job(project, job_id, command)
        return job_id
    except Exception as exc:
        set_job_failed(project["database"], job_id, str(exc))
        raise


def _legacy_target_file(project: dict, job: dict) -> Path | None:
    value = job.get("target_file")
    if value:
        path = Path(value)
        if path.is_file():
            return path

    local = project["root"] / "input" / "jobs" / job["id"] / "targets.txt"
    if local.is_file():
        return local

    connection = None
    try:
        from reconmancer.core.database import connect

        connection = connect(project["database"])
        row = connection.execute(
            """
            SELECT target_file
            FROM handoff_queue
            WHERE destination_job_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (job["id"],),
        ).fetchone()
        if row:
            path = project["root"] / row["target_file"]
            if path.is_file():
                return path
    except Exception:
        pass
    finally:
        if connection is not None:
            connection.close()

    return None


def retry_job(project: dict, job_id: str) -> str:
    job = get_job(project["database"], job_id)
    if job is None:
        raise ValueError("Job does not exist.")

    if job.get("status") not in {"failed", "interrupted", "stale"}:
        raise ValueError("Only failed/interrupted jobs can be retried.")

    try:
        payload = json.loads(job.get("payload_json") or "{}")
    except json.JSONDecodeError:
        payload = {}

    source_target_file = _legacy_target_file(project, job)
    if source_target_file is None:
        raise ValueError("Original target file is no longer available.")

    auth_profile_id = payload.get("auth_profile_id")

    return dispatch_scan_job(
        project,
        engine=job["engine"],
        payload=payload,
        target_file=source_target_file,
        auth_profile_id=auth_profile_id,
        retry_of=job_id,
        copy_target_file=True,
    )
