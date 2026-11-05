from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from reconmancer.core.database import connect


ARTIFACT_LIST_LIMIT = 200
RUN_LIST_LIMIT = 300


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(
    value: str | None,
) -> datetime | None:

    if not value:
        return None

    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    except (
        TypeError,
        ValueError,
    ):
        return None


def safe_relative_path(
    project_root: Path,
    relative_path: str | Path,
) -> Path | None:

    project_root = project_root.resolve()

    candidate = (project_root / Path(relative_path)).resolve()

    try:
        candidate.relative_to(project_root)

    except ValueError:
        return None

    return candidate


def path_stats(
    path: Path,
) -> dict:

    result = {
        "bytes": 0,
        "files": 0,
        "directories": 0,
    }

    try:
        if not path.exists():
            return result

    except OSError:
        return result

    if path.is_file():
        try:
            result["bytes"] = path.stat().st_size

            result["files"] = 1

        except OSError:
            pass

        return result

    stack = [path]

    while stack:
        current = stack.pop()

        result["directories"] += 1

        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    try:
                        if entry.is_symlink():
                            try:
                                result["bytes"] += entry.stat(
                                    follow_symlinks=False
                                ).st_size

                                result["files"] += 1

                            except OSError:
                                pass

                            continue

                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))

                            continue

                        if entry.is_file(follow_symlinks=False):
                            try:
                                result["bytes"] += entry.stat(
                                    follow_symlinks=False
                                ).st_size

                                result["files"] += 1

                            except OSError:
                                pass

                    except OSError:
                        continue

        except OSError:
            continue

    return result


def database_stats(
    db_path: Path,
) -> dict:

    output = {
        "bytes": 0,
        "files": 0,
        "directories": 0,
    }

    candidates = [
        db_path,
        Path(str(db_path) + "-wal"),
        Path(str(db_path) + "-shm"),
    ]

    for path in candidates:
        stats = path_stats(path)

        output["bytes"] += stats["bytes"]

        output["files"] += stats["files"]

    return output


def get_storage_categories(
    project_root: Path,
    db_path: Path,
) -> list[dict]:

    definitions = [
        (
            "database",
            "SQLite database",
            None,
        ),
        (
            "raw_httpx",
            "Raw HTTPX",
            Path("raw/httpx"),
        ),
        (
            "raw_katana",
            "Raw Katana",
            Path("raw/katana"),
        ),
        (
            "raw_nuclei",
            "Raw Nuclei",
            Path("raw/nuclei"),
        ),
        (
            "screenshots",
            "Screenshots",
            Path("objects/screenshots"),
        ),
        (
            "thumbnails",
            "Thumbnails",
            Path("objects/thumbnails"),
        ),
        (
            "responses",
            "Stored responses",
            Path("objects/responses"),
        ),
        (
            "evidence",
            "Evidence objects",
            Path("objects/evidence"),
        ),
        (
            "job_inputs",
            "Job inputs",
            Path("input/jobs"),
        ),
        (
            "handoff_inputs",
            "Handoff inputs",
            Path("input/handoffs"),
        ),
        (
            "logs",
            "Logs",
            Path("logs"),
        ),
        (
            "temp",
            "Temporary files",
            Path("temp"),
        ),
    ]

    categories = []

    known_bytes = 0

    for (
        key,
        label,
        relative,
    ) in definitions:
        if key == "database":
            stats = database_stats(db_path)

        else:
            stats = path_stats(project_root / relative)

        item = {
            "key": key,
            "label": label,
            "bytes": stats["bytes"],
            "files": stats["files"],
        }

        categories.append(item)

        known_bytes += item["bytes"]

    total = path_stats(project_root)

    other_bytes = max(
        0,
        total["bytes"] - known_bytes,
    )

    categories.append(
        {
            "key": "other",
            "label": ("Other project files"),
            "bytes": (other_bytes),
            "files": None,
        }
    )

    return categories


def list_run_storage(
    db_path: Path,
    project_root: Path,
    *,
    limit: int = RUN_LIST_LIMIT,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                engine,
                profile,
                status,
                started_at,
                finished_at,
                input_count,
                result_count

            FROM runs

            ORDER BY
                started_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    finally:
        connection.close()

    output = []

    for row in rows:
        item = dict(row)

        raw_path = project_root / "raw" / item["engine"] / item["id"]

        stats = path_stats(raw_path)

        item["raw_bytes"] = stats["bytes"]

        item["raw_files"] = stats["files"]

        output.append(item)

    return output


def quote_identifier(
    value: str,
) -> str:

    return (
        '"'
        + value.replace(
            '"',
            '""',
        )
        + '"'
    )


def hash_reference_columns(
    connection,
) -> list[
    tuple[
        str,
        str,
    ]
]:

    tables = connection.execute(
        """
        SELECT
            name

        FROM sqlite_master

        WHERE
            type = 'table'

            AND
            name NOT LIKE 'sqlite_%'

            AND
            name != 'objects'
        """
    ).fetchall()

    output = []

    for table_row in tables:
        table = table_row["name"]

        columns = connection.execute(
            f"""
            PRAGMA table_info(
                {quote_identifier(table)}
            )
            """
        ).fetchall()

        for column in columns:
            name = column["name"]

            if not name.endswith("_hash"):
                continue

            output.append(
                (
                    table,
                    name,
                )
            )

    return output


def build_hash_reference_counts(
    connection,
) -> dict[str, int]:

    columns = hash_reference_columns(connection)

    if not columns:
        return {}

    selects = []

    for (
        table,
        column,
    ) in columns:
        selects.append(
            f"""
            SELECT
                CAST(
                    {quote_identifier(column)}
                    AS TEXT
                ) AS hash_value

            FROM
                {quote_identifier(table)}

            WHERE
                {quote_identifier(column)}
                IS NOT NULL

                AND

                {quote_identifier(column)}
                != ''
            """
        )

    query = (
        """
        SELECT
            hash_value,

            COUNT(*) AS reference_count

        FROM (
        """
        + "\nUNION ALL\n".join(selects)
        + """
        )

        GROUP BY
            hash_value
        """
    )

    rows = connection.execute(query).fetchall()

    return {row["hash_value"]: int(row["reference_count"] or 0) for row in rows}


def list_artifacts(
    db_path: Path,
    *,
    limit: int = ARTIFACT_LIST_LIMIT,
) -> list[dict]:

    connection = connect(db_path)

    try:
        references = build_hash_reference_counts(connection)

        rows = connection.execute(
            """
            SELECT
                hash,
                kind,
                relative_path,
                size_bytes,
                compression,
                created_at

            FROM objects

            ORDER BY
                size_bytes DESC,
                created_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        output = []

        for row in rows:
            item = dict(row)

            item["references"] = references.get(
                item["hash"],
                0,
            )

            item["deletable"] = item["references"] == 0

            output.append(item)

        return output

    finally:
        connection.close()


def run_owned_tables(
    connection,
) -> list[str]:

    rows = connection.execute(
        """
        SELECT
            name

        FROM sqlite_master

        WHERE
            type = 'table'

            AND
            name NOT LIKE 'sqlite_%'
        """
    ).fetchall()

    output = []

    for row in rows:
        table = row["name"]

        if table in {
            "runs",
            "jobs",
        }:
            continue

        columns = connection.execute(
            f"""
            PRAGMA table_info(
                {quote_identifier(table)}
            )
            """
        ).fetchall()

        names = {column["name"] for column in columns}

        if "run_id" in names:
            output.append(table)

    return output


def preview_run_cleanup(
    db_path: Path,
    project_root: Path,
    run_id: str,
) -> dict | None:

    connection = connect(db_path)

    try:
        run = connection.execute(
            """
            SELECT
                id,
                engine,
                profile,
                status,
                started_at,
                finished_at,
                input_count,
                result_count,
                error

            FROM runs

            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()

        if run is None:
            return None

        run = dict(run)

        table_counts = []

        for table in run_owned_tables(connection):
            row = connection.execute(
                f"""
                SELECT
                    COUNT(*) AS row_count

                FROM
                    {quote_identifier(table)}

                WHERE
                    run_id = ?
                """,
                (run_id,),
            ).fetchone()

            count = int(row["row_count"] or 0)

            if count:
                table_counts.append(
                    {
                        "table": table,
                        "rows": (count),
                    }
                )

        linked_jobs = connection.execute(
            """
            SELECT
                id,
                status

            FROM jobs

            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchall()

        screenshot_hashes = []

        tables = {
            row["name"]
            for row in connection.execute(
                """
                SELECT
                    name

                FROM sqlite_master

                WHERE
                    type = 'table'
                """
            ).fetchall()
        }

        if "http_observations" in tables:
            rows = connection.execute(
                """
                SELECT DISTINCT
                    screenshot_hash

                FROM http_observations

                WHERE
                    run_id = ?

                    AND

                    screenshot_hash
                    IS NOT NULL
                """,
                (run_id,),
            ).fetchall()

            screenshot_hashes = [
                row["screenshot_hash"] for row in rows if row["screenshot_hash"]
            ]

        references = build_hash_reference_counts(connection)

        exclusive_artifacts = []

        for hash_value in screenshot_hashes:
            count_in_run = connection.execute(
                """
                SELECT
                    COUNT(*) AS row_count

                FROM http_observations

                WHERE
                    run_id = ?

                    AND

                    screenshot_hash = ?
                """,
                (
                    run_id,
                    hash_value,
                ),
            ).fetchone()["row_count"]

            if (
                references.get(
                    hash_value,
                    0,
                )
                != count_in_run
            ):
                continue

            obj = connection.execute(
                """
                SELECT
                    hash,
                    kind,
                    relative_path,
                    size_bytes

                FROM objects

                WHERE
                    hash = ?
                """,
                (hash_value,),
            ).fetchone()

            if obj is not None:
                exclusive_artifacts.append(dict(obj))

    finally:
        connection.close()

    raw_path = project_root / "raw" / run["engine"] / run_id

    raw_stats = path_stats(raw_path)

    artifact_bytes = sum(
        int(item.get("size_bytes") or 0) for item in exclusive_artifacts
    )

    return {
        "run": run,
        "database_rows": (table_counts),
        "database_row_total": sum(item["rows"] for item in table_counts),
        "linked_jobs": [dict(row) for row in linked_jobs],
        "raw_path": str(raw_path),
        "raw_bytes": (raw_stats["bytes"]),
        "raw_files": (raw_stats["files"]),
        "exclusive_artifacts": (exclusive_artifacts),
        "exclusive_artifact_bytes": (artifact_bytes),
        "estimated_file_bytes": (raw_stats["bytes"] + artifact_bytes),
    }


def remove_empty_parents(
    path: Path,
    stop: Path,
) -> None:

    stop = stop.resolve()

    current = path

    while True:
        try:
            current_resolved = current.resolve()

            current_resolved.relative_to(stop)

        except (
            OSError,
            ValueError,
        ):
            return

        if current_resolved == stop:
            return

        try:
            current.rmdir()

        except OSError:
            return

        current = current.parent


def delete_object_file(
    project_root: Path,
    relative_path: str | None,
) -> int:

    if not relative_path:
        return 0

    path = safe_relative_path(
        project_root,
        relative_path,
    )

    if path is None:
        return 0

    removed = 0

    try:
        if path.is_file():
            try:
                removed = path.stat().st_size

            except OSError:
                removed = 0

            path.unlink(missing_ok=True)

            remove_empty_parents(
                path.parent,
                project_root,
            )

    except OSError:
        pass

    return removed


def cleanup_unreferenced_artifact(
    db_path: Path,
    project_root: Path,
    hash_value: str,
) -> int:

    connection = connect(db_path)

    try:
        references = build_hash_reference_counts(connection)

        if (
            references.get(
                hash_value,
                0,
            )
            != 0
        ):
            return 0

        row = connection.execute(
            """
            SELECT
                relative_path

            FROM objects

            WHERE
                hash = ?
            """,
            (hash_value,),
        ).fetchone()

        if row is None:
            return 0

        relative_path = row["relative_path"]

        connection.execute(
            """
            DELETE FROM objects

            WHERE
                hash = ?
            """,
            (hash_value,),
        )

        connection.commit()

    finally:
        connection.close()

    removed = delete_object_file(
        project_root,
        relative_path,
    )

    thumbnail = project_root / "objects" / "thumbnails" / (hash_value + ".jpg")

    try:
        if thumbnail.is_file():
            try:
                removed += thumbnail.stat().st_size

            except OSError:
                pass

            thumbnail.unlink(missing_ok=True)

    except OSError:
        pass

    return removed


def delete_run(
    db_path: Path,
    project_root: Path,
    run_id: str,
) -> dict:

    preview = preview_run_cleanup(
        db_path,
        project_root,
        run_id,
    )

    if preview is None:
        raise ValueError("Run does not exist.")

    artifact_hashes = [item["hash"] for item in preview["exclusive_artifacts"]]

    connection = connect(db_path)

    try:
        connection.execute(
            """
            UPDATE jobs

            SET
                run_id = NULL

            WHERE
                run_id = ?
            """,
            (run_id,),
        )

        for table in run_owned_tables(connection):
            connection.execute(
                f"""
                DELETE FROM
                    {quote_identifier(table)}

                WHERE
                    run_id = ?
                """,
                (run_id,),
            )

        cursor = connection.execute(
            """
            DELETE FROM runs

            WHERE
                id = ?
            """,
            (run_id,),
        )

        if cursor.rowcount != 1:
            raise ValueError(("Run disappeared before deletion."))

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    removed_bytes = 0

    raw_path = project_root / "raw" / preview["run"]["engine"] / run_id

    safe_raw = None

    try:
        relative_raw = raw_path.relative_to(project_root)

        safe_raw = safe_relative_path(
            project_root,
            relative_raw,
        )

    except ValueError:
        safe_raw = None

    if safe_raw is not None and safe_raw.is_dir():
        raw_stats = path_stats(safe_raw)

        removed_bytes += raw_stats["bytes"]

        shutil.rmtree(
            safe_raw,
            ignore_errors=True,
        )

    artifact_removed = 0

    for hash_value in artifact_hashes:
        artifact_removed += cleanup_unreferenced_artifact(
            db_path,
            project_root,
            hash_value,
        )

    removed_bytes += artifact_removed

    return {
        "run_id": run_id,
        "removed_bytes": (removed_bytes),
        "artifacts_removed": len(artifact_hashes),
    }


def get_artifact(
    db_path: Path,
    hash_value: str,
) -> dict | None:

    connection = connect(db_path)

    try:
        references = build_hash_reference_counts(connection)

        row = connection.execute(
            """
            SELECT
                hash,
                kind,
                relative_path,
                size_bytes,
                compression,
                created_at

            FROM objects

            WHERE
                hash = ?
            """,
            (hash_value,),
        ).fetchone()

        if row is None:
            return None

        item = dict(row)

        item["references"] = references.get(
            hash_value,
            0,
        )

        item["deletable"] = item["references"] == 0

        return item

    finally:
        connection.close()


def delete_artifact(
    db_path: Path,
    project_root: Path,
    hash_value: str,
) -> dict:

    artifact = get_artifact(
        db_path,
        hash_value,
    )

    if artifact is None:
        raise ValueError("Artifact does not exist.")

    if not artifact["deletable"]:
        raise ValueError(("Artifact is still referenced and cannot be deleted."))

    removed = cleanup_unreferenced_artifact(
        db_path,
        project_root,
        hash_value,
    )

    return {
        "hash": hash_value,
        "removed_bytes": (removed),
    }


def terminal_jobs_before(
    db_path: Path,
    cutoff: datetime,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                engine,
                status,
                finished_at

            FROM jobs

            WHERE
                status IN (
                    'completed',
                    'failed'
                )
            """
        ).fetchall()

        output = []

        for row in rows:
            item = dict(row)

            finished = parse_datetime(item.get("finished_at"))

            if finished is None:
                continue

            if finished > cutoff:
                continue

            output.append(item)

        return output

    finally:
        connection.close()


def preview_maintenance(
    db_path: Path,
    project_root: Path,
    kind: str,
) -> dict:

    now = now_utc()

    files = []

    label = ""

    if kind == "temp":
        label = "Temporary files older than 24 hours"

        cutoff = now - timedelta(hours=24)

        root = project_root / "temp"

        if root.is_dir():
            for path in root.rglob("*"):
                if not path.is_file():
                    continue

                try:
                    modified = datetime.fromtimestamp(
                        path.stat().st_mtime,
                        tz=timezone.utc,
                    )

                except OSError:
                    continue

                if modified > cutoff:
                    continue

                files.append(path)

    elif kind == "job-inputs":
        label = "Completed job inputs older than 7 days"

        cutoff = now - timedelta(days=7)

        for job in terminal_jobs_before(
            db_path,
            cutoff,
        ):
            root = project_root / "input" / "jobs" / job["id"]

            if not root.exists():
                continue

            files.append(root)

    elif kind == "job-logs":
        label = "Completed job logs older than 30 days"

        cutoff = now - timedelta(days=30)

        for job in terminal_jobs_before(
            db_path,
            cutoff,
        ):
            path = project_root / "logs" / "jobs" / (job["id"] + ".log")

            if path.is_file():
                files.append(path)

    else:
        raise ValueError(("Unknown maintenance cleanup type."))

    total_bytes = 0
    total_files = 0

    entries = []

    for path in files:
        stats = path_stats(path)

        total_bytes += stats["bytes"]

        total_files += stats["files"]

        try:
            relative = str(path.relative_to(project_root))

        except ValueError:
            continue

        entries.append(
            {
                "path": relative,
                "bytes": stats["bytes"],
                "files": stats["files"],
            }
        )

    return {
        "kind": kind,
        "label": label,
        "bytes": (total_bytes),
        "files": (total_files),
        "entries": (entries),
    }


def execute_maintenance(
    db_path: Path,
    project_root: Path,
    kind: str,
) -> dict:

    preview = preview_maintenance(
        db_path,
        project_root,
        kind,
    )

    removed_bytes = 0

    for item in preview["entries"]:
        path = safe_relative_path(
            project_root,
            item["path"],
        )

        if path is None:
            continue

        if path.is_dir():
            removed_bytes += path_stats(path)["bytes"]

            shutil.rmtree(
                path,
                ignore_errors=True,
            )

        elif path.is_file():
            try:
                removed_bytes += path.stat().st_size

            except OSError:
                pass

            try:
                path.unlink(missing_ok=True)

            except OSError:
                pass

    return {
        "kind": kind,
        "removed_bytes": (removed_bytes),
    }


def build_storage_workspace(
    project: dict,
) -> dict:

    project_root = project["root"]

    db_path = project["database"]

    configured_limit_gb = float(
        project["config"]
        .get(
            "resources",
            {},
        )
        .get(
            "disk_limit_gb",
            10.0,
        )
    )

    limit_bytes = int(configured_limit_gb * 1024 * 1024 * 1024)

    total_stats = path_stats(project_root)

    used_bytes = total_stats["bytes"]

    percentage = 0.0

    if limit_bytes:
        percentage = min(
            100.0,
            (used_bytes / limit_bytes) * 100.0,
        )

    categories = get_storage_categories(
        project_root,
        db_path,
    )

    for item in categories:
        item["percentage"] = (item["bytes"] / used_bytes) * 100.0 if used_bytes else 0.0

    return {
        "used_bytes": (used_bytes),
        "limit_bytes": (limit_bytes),
        "free_budget_bytes": max(
            0,
            limit_bytes - used_bytes,
        ),
        "percentage": (percentage),
        "total_files": (total_stats["files"]),
        "categories": (categories),
        "runs": list_run_storage(
            db_path,
            project_root,
        ),
        "artifacts": list_artifacts(
            db_path,
        ),
    }
