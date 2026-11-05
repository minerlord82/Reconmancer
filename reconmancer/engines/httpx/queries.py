from __future__ import annotations

from pathlib import Path

from reconmancer.core.database import connect


DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500


def list_httpx_runs(
    db_path: Path,
    *,
    limit: int = 50,
) -> list[dict]:

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

            WHERE engine = 'httpx'

            ORDER BY started_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_httpx_run(
    db_path: Path,
    run_id: str,
) -> dict | None:

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
                AND engine = 'httpx'
            """,
            (run_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


def latest_httpx_run(
    db_path: Path,
) -> dict | None:

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
                error

            FROM runs

            WHERE engine = 'httpx'

            ORDER BY started_at DESC

            LIMIT 1
            """
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

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS count

            FROM http_observations

            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        return int(row["count"])

    finally:
        connection.close()


def list_run_observations(
    db_path: Path,
    run_id: str,
    *,
    page: int = 1,
    per_page: int = DEFAULT_PAGE_SIZE,
) -> list[dict]:

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
                h.id,

                u.url,

                a.host,

                h.status_code,
                h.title,

                h.method,

                h.content_type,
                h.content_length,

                h.response_time_ms,

                h.server,

                h.technologies_json,

                h.ip,
                h.cname,
                h.asn,

                h.cdn,
                h.cdn_name,
                h.cdn_type,

                h.redirect_location,

                h.body_hash,
                h.header_hash,

                h.favicon_hash,
                h.jarm,

                h.http2,
                h.websocket,

                h.screenshot_hash,

                h.context,

                h.created_at

            FROM http_observations h

            JOIN urls u
              ON u.id = h.url_id

            LEFT JOIN assets a
              ON a.id = u.asset_id

            WHERE h.run_id = ?

            ORDER BY h.id ASC

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


def list_run_redirects(
    db_path: Path,
    run_id: str,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                r.id,

                source.url
                    AS source,

                r.status_code,

                r.destination_url
                    AS destination,

                r.depth,

                r.context,

                r.created_at

            FROM redirects r

            JOIN urls source
              ON source.id =
                 r.source_url_id

            WHERE r.run_id = ?

            ORDER BY
                r.depth ASC,
                r.id ASC
            """,
            (run_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_run_stats(
    db_path: Path,
    run_id: str,
) -> dict:

    connection = connect(db_path)

    try:
        observations = connection.execute(
            """
                SELECT
                    COUNT(*) AS total,

                    SUM(
                        CASE
                            WHEN status_code
                                 BETWEEN 200 AND 299
                            THEN 1
                            ELSE 0
                        END
                    ) AS status_2xx,

                    SUM(
                        CASE
                            WHEN status_code
                                 BETWEEN 300 AND 399
                            THEN 1
                            ELSE 0
                        END
                    ) AS status_3xx,

                    SUM(
                        CASE
                            WHEN status_code
                                 BETWEEN 400 AND 499
                            THEN 1
                            ELSE 0
                        END
                    ) AS status_4xx,

                    SUM(
                        CASE
                            WHEN status_code >= 500
                            THEN 1
                            ELSE 0
                        END
                    ) AS status_5xx,

                    SUM(
                        CASE
                            WHEN screenshot_hash
                                 IS NOT NULL
                            THEN 1
                            ELSE 0
                        END
                    ) AS screenshots

                FROM http_observations

                WHERE run_id = ?
                """,
            (run_id,),
        ).fetchone()

        redirect_row = connection.execute(
            """
                SELECT
                    COUNT(*) AS count

                FROM redirects

                WHERE run_id = ?
                """,
            (run_id,),
        ).fetchone()

        return {
            "total": (observations["total"] or 0),
            "status_2xx": (observations["status_2xx"] or 0),
            "status_3xx": (observations["status_3xx"] or 0),
            "status_4xx": (observations["status_4xx"] or 0),
            "status_5xx": (observations["status_5xx"] or 0),
            "screenshots": (observations["screenshots"] or 0),
            "redirects": (redirect_row["count"] or 0),
        }

    finally:
        connection.close()
