from __future__ import annotations

from pathlib import Path

from reconmancer.core.database import connect

from reconmancer.engines.nuclei.schema import (
    ensure_nuclei_schema,
)


DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500


def list_nuclei_runs(
    db_path: Path,
    *,
    limit: int = 50,
) -> list[dict]:

    ensure_nuclei_schema(db_path)

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                profile,
                context,
                status,
                started_at,
                finished_at,
                input_count,
                result_count,
                error

            FROM runs

            WHERE engine = 'nuclei'

            ORDER BY started_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def latest_nuclei_run(
    db_path: Path,
) -> dict | None:

    ensure_nuclei_schema(db_path)

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT
                id,
                profile,
                context,
                status,
                started_at,
                finished_at,
                input_count,
                result_count,
                error

            FROM runs

            WHERE engine = 'nuclei'

            ORDER BY started_at DESC

            LIMIT 1
            """
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


def get_nuclei_run(
    db_path: Path,
    run_id: str,
) -> dict | None:

    ensure_nuclei_schema(db_path)

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT
                id,
                engine,
                profile,
                context,
                status,
                started_at,
                finished_at,
                input_count,
                result_count,
                command_json,
                error

            FROM runs

            WHERE
                id = ?
                AND engine = 'nuclei'
            """,
            (run_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


def count_run_findings(
    db_path: Path,
    run_id: str,
) -> int:

    ensure_nuclei_schema(db_path)

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS count

            FROM nuclei_findings

            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        return int(row["count"] or 0)

    finally:
        connection.close()


def list_run_findings(
    db_path: Path,
    run_id: str,
    *,
    page: int = 1,
    per_page: int = DEFAULT_PAGE_SIZE,
) -> list[dict]:

    ensure_nuclei_schema(db_path)

    page = max(
        1,
        int(page),
    )

    per_page = max(
        1,
        min(
            int(per_page),
            MAX_PAGE_SIZE,
        ),
    )

    offset = (page - 1) * per_page

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                id,

                template_id,
                template_path,

                matcher_name,

                name,
                severity,

                protocol,

                host,
                url,
                matched_at,

                ip,
                port,

                tags_json,

                description,

                references_json,

                cve_json,
                cwe_json,

                cvss_score,

                extracted_results_json,

                timestamp,
                created_at

            FROM nuclei_findings

            WHERE run_id = ?

            ORDER BY

                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END,

                id ASC

            LIMIT ?
            OFFSET ?
            """,
            (
                run_id,
                per_page,
                offset,
            ),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_run_stats(
    db_path: Path,
    run_id: str,
) -> dict:

    ensure_nuclei_schema(db_path)

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT

                COUNT(*)
                    AS total,

                COUNT(
                    DISTINCT template_id
                )
                    AS templates,

                COUNT(
                    DISTINCT host
                )
                    AS hosts,

                SUM(
                    CASE
                        WHEN severity = 'critical'
                        THEN 1
                        ELSE 0
                    END
                )
                    AS critical,

                SUM(
                    CASE
                        WHEN severity = 'high'
                        THEN 1
                        ELSE 0
                    END
                )
                    AS high,

                SUM(
                    CASE
                        WHEN severity = 'medium'
                        THEN 1
                        ELSE 0
                    END
                )
                    AS medium,

                SUM(
                    CASE
                        WHEN severity = 'low'
                        THEN 1
                        ELSE 0
                    END
                )
                    AS low,

                SUM(
                    CASE
                        WHEN severity = 'info'
                        THEN 1
                        ELSE 0
                    END
                )
                    AS info

            FROM nuclei_findings

            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        return {
            "total": (row["total"] or 0),
            "templates": (row["templates"] or 0),
            "hosts": (row["hosts"] or 0),
            "critical": (row["critical"] or 0),
            "high": (row["high"] or 0),
            "medium": (row["medium"] or 0),
            "low": (row["low"] or 0),
            "info": (row["info"] or 0),
        }

    finally:
        connection.close()
