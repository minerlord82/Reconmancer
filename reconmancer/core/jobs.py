from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from reconmancer.core.database import connect


JOB_COLUMN_MIGRATIONS = {
    "heartbeat_at": "TEXT",
    "worker_pid": "INTEGER",
    "attempt": "INTEGER NOT NULL DEFAULT 1",
    "retry_of": "TEXT",
    "target_file": "TEXT",
    "error": "TEXT",
    "updated_at": "TEXT",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def ensure_job_schema(db_path: Path) -> None:
    connection = connect(db_path)
    try:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
        }

        for name, column_type in JOB_COLUMN_MIGRATIONS.items():
            if name in columns:
                continue
            connection.execute(f"ALTER TABLE jobs ADD COLUMN {name} {column_type}")

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_heartbeat ON jobs(heartbeat_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_retry_of ON jobs(retry_of)"
        )
        connection.commit()
    finally:
        connection.close()


def create_job(
    db_path: Path,
    *,
    engine: str,
    payload: dict,
    retry_of: str | None = None,
) -> str:
    ensure_job_schema(db_path)
    job_id = uuid.uuid4().hex[:12]
    attempt = 1

    connection = connect(db_path)
    try:
        if retry_of:
            parent = connection.execute(
                "SELECT attempt FROM jobs WHERE id = ?",
                (retry_of,),
            ).fetchone()
            if parent:
                attempt = int(parent["attempt"] or 1) + 1

        timestamp = now_iso()
        connection.execute(
            """
            INSERT INTO jobs (
                id,
                engine,
                status,
                created_at,
                payload_json,
                attempt,
                retry_of,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                engine,
                "queued",
                timestamp,
                json.dumps(payload, sort_keys=True),
                attempt,
                retry_of,
                timestamp,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return job_id


def set_job_target_file(
    db_path: Path,
    job_id: str,
    target_file: Path | str,
) -> None:
    ensure_job_schema(db_path)
    connection = connect(db_path)
    try:
        connection.execute(
            """
            UPDATE jobs
            SET target_file = ?, updated_at = ?
            WHERE id = ?
            """,
            (str(target_file), now_iso(), job_id),
        )
        connection.commit()
    finally:
        connection.close()


def set_job_running(
    db_path: Path,
    job_id: str,
    *,
    worker_pid: int | None = None,
) -> None:
    ensure_job_schema(db_path)
    timestamp = now_iso()
    pid = worker_pid if worker_pid is not None else os.getpid()
    connection = connect(db_path)
    try:
        connection.execute(
            """
            UPDATE jobs
            SET
                status = 'running',
                started_at = COALESCE(started_at, ?),
                heartbeat_at = ?,
                worker_pid = ?,
                updated_at = ?,
                error = NULL
            WHERE id = ?
            """,
            (timestamp, timestamp, pid, timestamp, job_id),
        )
        connection.commit()
    finally:
        connection.close()


def heartbeat_job(db_path: Path, job_id: str) -> None:
    ensure_job_schema(db_path)
    timestamp = now_iso()
    connection = connect(db_path)
    try:
        connection.execute(
            """
            UPDATE jobs
            SET heartbeat_at = ?, updated_at = ?
            WHERE id = ? AND status = 'running'
            """,
            (timestamp, timestamp, job_id),
        )
        connection.commit()
    finally:
        connection.close()


def attach_job_run(db_path: Path, job_id: str, run_id: str) -> None:
    ensure_job_schema(db_path)
    connection = connect(db_path)
    try:
        connection.execute(
            """
            UPDATE jobs
            SET run_id = ?, updated_at = ?
            WHERE id = ?
            """,
            (run_id, now_iso(), job_id),
        )
        connection.commit()
    finally:
        connection.close()


def set_job_completed(
    db_path: Path,
    job_id: str,
    *,
    run_id: str,
) -> None:
    ensure_job_schema(db_path)
    timestamp = now_iso()
    connection = connect(db_path)
    try:
        connection.execute(
            """
            UPDATE jobs
            SET
                status = 'completed',
                finished_at = ?,
                heartbeat_at = ?,
                run_id = ?,
                updated_at = ?,
                error = NULL
            WHERE id = ?
            """,
            (timestamp, timestamp, run_id, timestamp, job_id),
        )
        connection.commit()
    finally:
        connection.close()


def set_job_failed(
    db_path: Path,
    job_id: str,
    error: str | None = None,
) -> None:
    ensure_job_schema(db_path)
    timestamp = now_iso()
    connection = connect(db_path)
    try:
        connection.execute(
            """
            UPDATE jobs
            SET
                status = 'failed',
                finished_at = ?,
                heartbeat_at = ?,
                updated_at = ?,
                error = ?
            WHERE id = ?
            """,
            (timestamp, timestamp, timestamp, error, job_id),
        )
        connection.commit()
    finally:
        connection.close()


def set_job_interrupted(
    db_path: Path,
    job_id: str,
    reason: str,
) -> None:
    ensure_job_schema(db_path)
    timestamp = now_iso()
    connection = connect(db_path)
    try:
        connection.execute(
            """
            UPDATE jobs
            SET
                status = 'interrupted',
                finished_at = ?,
                updated_at = ?,
                error = ?
            WHERE id = ? AND status IN ('queued', 'running', 'stale')
            """,
            (timestamp, timestamp, reason[:2000], job_id),
        )
        connection.commit()
    finally:
        connection.close()


def get_job(db_path: Path, job_id: str) -> dict | None:
    ensure_job_schema(db_path)
    connection = connect(db_path)
    try:
        row = connection.execute(
            "SELECT * FROM jobs WHERE id = ?",
            (job_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def list_engine_jobs(
    db_path: Path,
    engine: str,
    *,
    limit: int = 20,
) -> list[dict]:
    ensure_job_schema(db_path)
    connection = connect(db_path)
    try:
        rows = connection.execute(
            """
            SELECT *
            FROM jobs
            WHERE engine = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (engine, limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def list_jobs(
    db_path: Path,
    *,
    status: str = "",
    limit: int = 300,
) -> list[dict]:
    ensure_job_schema(db_path)
    connection = connect(db_path)
    try:
        if status:
            rows = connection.execute(
                """
                SELECT * FROM jobs
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (status, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM jobs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def _pid_alive(pid: int | None) -> bool:
    if not pid or int(pid) <= 0:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def recover_stale_jobs(
    db_path: Path,
    *,
    heartbeat_timeout_seconds: int = 120,
    queued_timeout_seconds: int = 600,
) -> dict:
    ensure_job_schema(db_path)
    now = datetime.now(timezone.utc)
    summary = {
        "checked": 0,
        "interrupted": 0,
        "healthy": 0,
    }

    connection = connect(db_path)
    try:
        rows = connection.execute(
            """
            SELECT * FROM jobs
            WHERE status IN ('queued', 'running', 'stale')
            ORDER BY created_at ASC
            """
        ).fetchall()
    finally:
        connection.close()

    for row in rows:
        job = dict(row)
        summary["checked"] += 1
        status = job.get("status")

        if status == "queued":
            created = _parse_time(job.get("created_at"))
            if created and (now - created).total_seconds() > queued_timeout_seconds:
                set_job_interrupted(
                    db_path,
                    job["id"],
                    "Queued job never started before recovery timeout.",
                )
                summary["interrupted"] += 1
            else:
                summary["healthy"] += 1
            continue

        heartbeat = _parse_time(job.get("heartbeat_at") or job.get("started_at"))
        age = (now - heartbeat).total_seconds() if heartbeat else float("inf")
        alive = _pid_alive(job.get("worker_pid"))

        if not alive and age > heartbeat_timeout_seconds:
            set_job_interrupted(
                db_path,
                job["id"],
                "Worker process is no longer running; job recovered as interrupted.",
            )
            summary["interrupted"] += 1
        else:
            summary["healthy"] += 1

    return summary


def job_health(job: dict, *, stale_seconds: int = 120) -> str:
    status = str(job.get("status") or "")
    if status != "running":
        return status

    heartbeat = _parse_time(job.get("heartbeat_at") or job.get("started_at"))
    if heartbeat is None:
        return "stale"

    age = (datetime.now(timezone.utc) - heartbeat).total_seconds()
    if age > stale_seconds:
        return "stale"

    return "running"


class JobHeartbeat:
    def __init__(
        self,
        db_path: Path,
        job_id: str,
        *,
        interval_seconds: int = 15,
    ) -> None:
        self.db_path = db_path
        self.job_id = job_id
        self.interval_seconds = max(5, int(interval_seconds))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                heartbeat_job(self.db_path, self.job_id)
            except Exception:
                # Heartbeats must never kill the scan worker.
                pass

    def __enter__(self):
        heartbeat_job(self.db_path, self.job_id)
        self._thread = threading.Thread(
            target=self._run,
            name=f"reconmancer-heartbeat-{self.job_id}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            heartbeat_job(self.db_path, self.job_id)
        except Exception:
            pass


def recover_projects_on_startup(home: Path) -> dict:
    projects_root = home / "projects"
    output = {
        "projects": 0,
        "interrupted": 0,
    }

    if not projects_root.is_dir():
        return output

    for entry in projects_root.iterdir():
        db_path = entry / "recon.db"
        if not db_path.is_file():
            continue
        try:
            result = recover_stale_jobs(db_path)
        except Exception:
            continue
        output["projects"] += 1
        output["interrupted"] += result["interrupted"]

    return output
