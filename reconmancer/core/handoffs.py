from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from reconmancer.core.database import connect


MAX_HANDOFF_TARGETS = 100000


SCHEMA = """
CREATE TABLE IF NOT EXISTS handoff_queue (

    id TEXT PRIMARY KEY,

    source_engine TEXT NOT NULL,
    source_run_id TEXT NOT NULL,

    destination_engine TEXT NOT NULL,
    destination_profile TEXT,

    status TEXT NOT NULL,

    target_count INTEGER NOT NULL
        DEFAULT 0,

    target_file TEXT NOT NULL,

    options_json TEXT,

    destination_job_id TEXT,

    created_at TEXT NOT NULL,

    launched_at TEXT,

    error TEXT
);


CREATE TABLE IF NOT EXISTS handoff_items (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    handoff_id TEXT NOT NULL,

    target TEXT NOT NULL,

    source_engine TEXT NOT NULL,

    source_run_id TEXT NOT NULL,

    source_record_id INTEGER,

    provenance_json TEXT,

    created_at TEXT NOT NULL,

    FOREIGN KEY(handoff_id)
        REFERENCES handoff_queue(id)
        ON DELETE CASCADE,

    UNIQUE(
        handoff_id,
        target
    )
);


CREATE INDEX IF NOT EXISTS
idx_handoff_queue_source
ON handoff_queue(
    source_engine,
    source_run_id
);


CREATE INDEX IF NOT EXISTS
idx_handoff_queue_destination
ON handoff_queue(
    destination_engine
);


CREATE INDEX IF NOT EXISTS
idx_handoff_queue_job
ON handoff_queue(
    destination_job_id
);


CREATE INDEX IF NOT EXISTS
idx_handoff_items_handoff
ON handoff_items(
    handoff_id
);


CREATE INDEX IF NOT EXISTS
idx_handoff_items_target
ON handoff_items(
    target
);
"""


def now_iso() -> str:

    return datetime.now(timezone.utc).isoformat()


def ensure_handoff_schema(
    db_path: Path,
) -> None:

    connection = connect(db_path)

    try:
        connection.executescript(SCHEMA)

        connection.commit()

    finally:
        connection.close()


def collect_httpx_targets(
    db_path: Path,
    run_id: str,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                h.id
                    AS source_record_id,

                u.normalized_url
                    AS target,

                h.status_code,
                h.title,
                h.method,
                h.context

            FROM http_observations h

            JOIN urls u
              ON u.id = h.url_id

            WHERE
                h.run_id = ?
                AND (
                    u.normalized_url
                        LIKE 'http://%'
                    OR
                    u.normalized_url
                        LIKE 'https://%'
                )

            ORDER BY h.id ASC
            """,
            (run_id,),
        ).fetchall()

        output = []

        for row in rows:
            output.append(
                {
                    "target": (row["target"]),
                    "source_record_id": (row["source_record_id"]),
                    "provenance": {
                        "status_code": (row["status_code"]),
                        "title": (row["title"]),
                        "method": (row["method"]),
                        "context": (row["context"]),
                        "reason": ("httpx_observation"),
                    },
                }
            )

        return output

    finally:
        connection.close()


def collect_katana_targets(
    db_path: Path,
    run_id: str,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                id
                    AS source_record_id,

                normalized_url
                    AS target,

                method,
                status_code,

                source_kind,

                is_javascript,
                is_query,
                is_runtime,
                is_xhr,

                source_url

            FROM katana_observations

            WHERE
                run_id = ?
                AND (
                    normalized_url
                        LIKE 'http://%'
                    OR
                    normalized_url
                        LIKE 'https://%'
                )

            ORDER BY id ASC
            """,
            (run_id,),
        ).fetchall()

        output = []

        for row in rows:
            output.append(
                {
                    "target": (row["target"]),
                    "source_record_id": (row["source_record_id"]),
                    "provenance": {
                        "method": (row["method"]),
                        "status_code": (row["status_code"]),
                        "source_kind": (row["source_kind"]),
                        "is_javascript": (bool(row["is_javascript"])),
                        "is_query": (bool(row["is_query"])),
                        "is_runtime": (bool(row["is_runtime"])),
                        "is_xhr": (bool(row["is_xhr"])),
                        "source_url": (row["source_url"]),
                        "reason": ("katana_discovery"),
                    },
                }
            )

        return output

    finally:
        connection.close()


def collect_nuclei_targets(
    db_path: Path,
    run_id: str,
) -> list[dict]:
    connection = connect(db_path)
    try:
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(nuclei_findings)"
            ).fetchall()
        }
        if not {"id", "run_id"}.issubset(columns):
            return []
        target_expr = (
            "matched_at"
            if "matched_at" in columns
            else (
                "url" if "url" in columns else ("host" if "host" in columns else "NULL")
            )
        )
        severity_expr = "severity" if "severity" in columns else "NULL"
        template_expr = "template_id" if "template_id" in columns else "NULL"
        name_expr = "name" if "name" in columns else "NULL"
        rows = connection.execute(
            f"""
            SELECT
                id AS source_record_id,
                {target_expr} AS target,
                {severity_expr} AS severity,
                {template_expr} AS template_id,
                {name_expr} AS name
            FROM nuclei_findings
            WHERE run_id = ?
            ORDER BY id ASC
            """,
            (run_id,),
        ).fetchall()
        output = []
        for row in rows:
            target = row["target"]
            if not isinstance(target, str) or not target.startswith(
                ("http://", "https://")
            ):
                continue
            output.append(
                {
                    "target": target,
                    "source_record_id": row["source_record_id"],
                    "provenance": {
                        "severity": row["severity"],
                        "template_id": row["template_id"],
                        "name": row["name"],
                        "reason": "nuclei_finding",
                    },
                }
            )
        return output
    finally:
        connection.close()


def create_handoff(
    *,
    db_path: Path,
    project_root: Path,
    source_engine: str,
    source_run_id: str,
    destination_engine: str,
    destination_profile: str | None,
    targets: list[dict],
    options: dict,
) -> dict:

    ensure_handoff_schema(db_path)

    handoff_id = "HO-" + uuid.uuid4().hex[:12]

    deduplicated = []

    seen = set()

    for item in targets:
        target = str(
            item.get(
                "target",
                "",
            )
        )

        target = (
            target.replace(
                "\r",
                "",
            )
            .replace(
                "\n",
                "",
            )
            .strip()
        )

        if not target:
            continue

        if target in seen:
            continue

        seen.add(target)

        deduplicated.append(
            {
                "target": target,
                "source_engine": (item.get("source_engine") or source_engine),
                "source_run_id": (item.get("source_run_id") or source_run_id),
                "source_record_id": (item.get("source_record_id")),
                "provenance": (item.get("provenance") or {}),
            }
        )

        if len(deduplicated) > MAX_HANDOFF_TARGETS:
            raise ValueError(
                (f"Handoff exceeds {MAX_HANDOFF_TARGETS:,} unique targets.")
            )

    if not deduplicated:
        raise ValueError("Handoff contains no targets.")

    relative_directory = Path("input") / "handoffs" / handoff_id

    absolute_directory = project_root / relative_directory

    absolute_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    relative_target_file = relative_directory / "targets.txt"

    absolute_target_file = project_root / relative_target_file

    with absolute_target_file.open(
        "w",
        encoding="utf-8",
    ) as handle:
        for item in deduplicated:
            handle.write(item["target"])

            handle.write("\n")

    created_at = now_iso()

    connection = connect(db_path)

    try:
        connection.execute(
            """
            INSERT INTO handoff_queue (

                id,

                source_engine,
                source_run_id,

                destination_engine,
                destination_profile,

                status,

                target_count,

                target_file,

                options_json,

                created_at
            )

            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            """,
            (
                handoff_id,
                source_engine,
                source_run_id,
                destination_engine,
                destination_profile,
                "queued",
                len(deduplicated),
                str(relative_target_file),
                json.dumps(
                    options,
                    sort_keys=True,
                ),
                created_at,
            ),
        )

        rows = []

        for item in deduplicated:
            rows.append(
                (
                    handoff_id,
                    item["target"],
                    item["source_engine"],
                    item["source_run_id"],
                    item["source_record_id"],
                    json.dumps(
                        item["provenance"],
                        sort_keys=True,
                    ),
                    created_at,
                )
            )

        connection.executemany(
            """
            INSERT INTO handoff_items (

                handoff_id,

                target,

                source_engine,
                source_run_id,

                source_record_id,

                provenance_json,

                created_at
            )

            VALUES (
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?
            )
            """,
            rows,
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "id": handoff_id,
        "target_count": (len(deduplicated)),
        "target_file": (absolute_target_file),
    }


def attach_destination_job(
    db_path: Path,
    handoff_id: str,
    job_id: str,
) -> None:

    ensure_handoff_schema(db_path)

    connection = connect(db_path)

    try:
        connection.execute(
            """
            UPDATE handoff_queue

            SET
                destination_job_id = ?,
                status = 'launched',
                launched_at = ?

            WHERE id = ?
            """,
            (
                job_id,
                now_iso(),
                handoff_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def mark_handoff_failed(
    db_path: Path,
    handoff_id: str,
    error: str,
) -> None:

    ensure_handoff_schema(db_path)

    connection = connect(db_path)

    try:
        connection.execute(
            """
            UPDATE handoff_queue

            SET
                status = 'failed',
                error = ?

            WHERE id = ?
            """,
            (
                error,
                handoff_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def list_handoffs(
    db_path: Path,
    *,
    source_engine: str | None = None,
    source_run_id: str | None = None,
    destination_engine: str | None = None,
    limit: int = 50,
) -> list[dict]:

    ensure_handoff_schema(db_path)

    conditions = []

    parameters = []

    if source_engine is not None:
        conditions.append("q.source_engine = ?")

        parameters.append(source_engine)

    if source_run_id is not None:
        conditions.append("q.source_run_id = ?")

        parameters.append(source_run_id)

    if destination_engine is not None:
        conditions.append("q.destination_engine = ?")

        parameters.append(destination_engine)

    where = ""

    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    parameters.append(limit)

    connection = connect(db_path)

    try:
        rows = connection.execute(
            f"""
            SELECT
                q.id,

                q.source_engine,
                q.source_run_id,

                q.destination_engine,
                q.destination_profile,

                q.status
                    AS handoff_status,

                q.target_count,

                q.target_file,

                q.destination_job_id,

                q.created_at,
                q.launched_at,

                q.error,

                j.status
                    AS job_status,

                j.run_id
                    AS destination_run_id,

                COALESCE(
                    j.status,
                    q.status
                )
                    AS effective_status

            FROM handoff_queue q

            LEFT JOIN jobs j
              ON j.id =
                 q.destination_job_id

            {where}

            ORDER BY
                q.created_at DESC

            LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
