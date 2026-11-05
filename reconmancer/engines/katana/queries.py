from __future__ import annotations

from pathlib import Path

from reconmancer.core.database import connect

from reconmancer.engines.katana.schema import (
    ensure_katana_schema,
)


DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500


def list_katana_runs(
    db_path: Path,
    *,
    limit: int = 50,
) -> list[dict]:

    ensure_katana_schema(db_path)

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

            WHERE engine = 'katana'

            ORDER BY started_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def latest_katana_run(
    db_path: Path,
) -> dict | None:

    ensure_katana_schema(db_path)

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

            WHERE engine = 'katana'

            ORDER BY started_at DESC

            LIMIT 1
            """
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


def get_katana_run(
    db_path: Path,
    run_id: str,
) -> dict | None:

    ensure_katana_schema(db_path)

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
                AND engine = 'katana'
            """,
            (run_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


def count_run_observations(
    db_path: Path,
    run_id: str,
) -> int:

    ensure_katana_schema(db_path)

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS count

            FROM katana_observations

            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        return int(row["count"] or 0)

    finally:
        connection.close()


def list_run_observations(
    db_path: Path,
    run_id: str,
    *,
    page: int = 1,
    per_page: int = DEFAULT_PAGE_SIZE,
) -> list[dict]:

    ensure_katana_schema(db_path)

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

                profile,

                url,
                normalized_url,

                host,
                path,
                query_signature,

                source_url,

                method,
                status_code,

                content_type,

                tag,
                attribute,

                technologies_json,
                query_keys_json,

                is_javascript,
                is_query,
                is_xhr,
                is_runtime,

                source_kind,

                created_at

            FROM katana_observations

            WHERE run_id = ?

            ORDER BY id ASC

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


def list_run_groups(
    db_path: Path,
    run_id: str,
    *,
    limit: int = 500,
) -> list[dict]:

    ensure_katana_schema(db_path)

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                host,
                path,
                query_signature,

                MIN(
                    normalized_url
                ) AS example_url,

                COUNT(*)
                    AS discoveries,

                COUNT(
                    DISTINCT normalized_url
                ) AS variants,

                GROUP_CONCAT(
                    DISTINCT method
                ) AS methods,

                SUM(
                    CASE
                        WHEN is_javascript = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS javascript,

                SUM(
                    CASE
                        WHEN is_runtime = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS runtime,

                SUM(
                    CASE
                        WHEN is_xhr = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS xhr

            FROM katana_observations

            WHERE run_id = ?

            GROUP BY
                host,
                path,
                query_signature

            ORDER BY
                discoveries DESC,
                host ASC,
                path ASC

            LIMIT ?
            """,
            (
                run_id,
                limit,
            ),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_run_stats(
    db_path: Path,
    run_id: str,
) -> dict:

    ensure_katana_schema(db_path)

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT

                COUNT(*)
                    AS total,

                COUNT(
                    DISTINCT normalized_url
                )
                    AS unique_urls,

                COUNT(
                    DISTINCT host
                )
                    AS hosts,

                COUNT(
                    DISTINCT (
                        COALESCE(
                            host,
                            ''
                        )
                        || '|'
                        ||
                        COALESCE(
                            path,
                            ''
                        )
                        || '|'
                        ||
                        COALESCE(
                            query_signature,
                            ''
                        )
                    )
                )
                    AS endpoint_groups,

                SUM(
                    CASE
                        WHEN is_javascript = 1
                        THEN 1
                        ELSE 0
                    END
                )
                    AS javascript,

                SUM(
                    CASE
                        WHEN is_query = 1
                        THEN 1
                        ELSE 0
                    END
                )
                    AS query_urls,

                SUM(
                    CASE
                        WHEN is_runtime = 1
                        THEN 1
                        ELSE 0
                    END
                )
                    AS runtime,

                SUM(
                    CASE
                        WHEN is_xhr = 1
                        THEN 1
                        ELSE 0
                    END
                )
                    AS xhr,

                SUM(
                    CASE
                        WHEN (
                            source_kind = 'form'
                            OR LOWER(
                                COALESCE(
                                    tag,
                                    ''
                                )
                            ) = 'form'
                        )
                        THEN 1
                        ELSE 0
                    END
                )
                    AS forms,

                SUM(
                    CASE
                        WHEN status_code
                             BETWEEN 200 AND 299
                        THEN 1
                        ELSE 0
                    END
                )
                    AS status_2xx,

                SUM(
                    CASE
                        WHEN status_code
                             BETWEEN 300 AND 399
                        THEN 1
                        ELSE 0
                    END
                )
                    AS status_3xx,

                SUM(
                    CASE
                        WHEN status_code
                             BETWEEN 400 AND 499
                        THEN 1
                        ELSE 0
                    END
                )
                    AS status_4xx

            FROM katana_observations

            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        return {
            "total": (row["total"] or 0),
            "unique_urls": (row["unique_urls"] or 0),
            "hosts": (row["hosts"] or 0),
            "endpoint_groups": (row["endpoint_groups"] or 0),
            "javascript": (row["javascript"] or 0),
            "query_urls": (row["query_urls"] or 0),
            "runtime": (row["runtime"] or 0),
            "xhr": (row["xhr"] or 0),
            "forms": (row["forms"] or 0),
            "status_2xx": (row["status_2xx"] or 0),
            "status_3xx": (row["status_3xx"] or 0),
            "status_4xx": (row["status_4xx"] or 0),
        }

    finally:
        connection.close()
