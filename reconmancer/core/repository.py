from __future__ import annotations

import json
from datetime import (
    datetime,
    timezone,
)
from pathlib import Path
from urllib.parse import (
    urlsplit,
    urlunsplit,
)

from reconmancer.core.database import connect


def now_iso() -> str:

    return datetime.now(timezone.utc).isoformat()


def normalize_url(
    value: str,
) -> str:

    value = value.strip()

    parts = urlsplit(value)

    scheme = parts.scheme.lower()

    hostname = parts.hostname.lower() if parts.hostname else ""

    port = parts.port

    if port:
        default_port = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )

        if default_port:
            netloc = hostname

        else:
            netloc = f"{hostname}:{port}"

    else:
        netloc = hostname

    path = parts.path or "/"

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parts.query,
            "",
        )
    )


def next_run_id(
    db_path: Path,
    engine: str,
) -> str:

    prefixes = {
        "httpx": "H",
        "katana": "K",
        "nuclei": "N",
    }

    prefix = prefixes[engine]

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT id
            FROM runs
            WHERE engine = ?
            """,
            (engine,),
        ).fetchall()

        highest = 0

        for row in rows:
            run_id = row["id"]

            if not run_id.startswith(prefix + "-"):
                continue

            try:
                number = int(
                    run_id.split(
                        "-",
                        1,
                    )[1]
                )

            except (
                ValueError,
                IndexError,
            ):
                continue

            highest = max(
                highest,
                number,
            )

        return f"{prefix}-{highest + 1:04d}"

    finally:
        connection.close()


def create_run(
    db_path: Path,
    run_id: str,
    engine: str,
    profile: str,
    context: str = "anonymous",
    command: list[str] | None = None,
) -> None:

    connection = connect(db_path)

    try:
        connection.execute(
            """
            INSERT INTO runs (
                id,
                engine,
                profile,
                context,
                status,
                started_at,
                command_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                engine,
                profile,
                context,
                "running",
                now_iso(),
                json.dumps(command or []),
            ),
        )

        connection.commit()

    finally:
        connection.close()


def finish_run(
    db_path: Path,
    run_id: str,
    *,
    status: str,
    input_count: int,
    result_count: int,
    error: str | None = None,
) -> None:

    connection = connect(db_path)

    try:
        connection.execute(
            """
            UPDATE runs

            SET
                status = ?,
                finished_at = ?,
                input_count = ?,
                result_count = ?,
                error = ?

            WHERE id = ?
            """,
            (
                status,
                now_iso(),
                input_count,
                result_count,
                error,
                run_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def upsert_asset(
    db_path: Path,
    host: str,
) -> int:

    host = host.lower().strip()

    timestamp = now_iso()

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT id
            FROM assets
            WHERE host = ?
            """,
            (host,),
        ).fetchone()

        if row:
            connection.execute(
                """
                UPDATE assets
                SET last_seen = ?
                WHERE id = ?
                """,
                (
                    timestamp,
                    row["id"],
                ),
            )

            connection.commit()

            return row["id"]

        cursor = connection.execute(
            """
            INSERT INTO assets (
                host,
                first_seen,
                last_seen
            )

            VALUES (?, ?, ?)
            """,
            (
                host,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

        return cursor.lastrowid

    finally:
        connection.close()


def upsert_url(
    db_path: Path,
    url: str,
) -> int:

    normalized = normalize_url(url)

    parts = urlsplit(normalized)

    hostname = parts.hostname

    if not hostname:
        raise ValueError(f"URL has no hostname: {url}")

    asset_id = upsert_asset(
        db_path,
        hostname,
    )

    timestamp = now_iso()

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT id
            FROM urls
            WHERE url = ?
            """,
            (normalized,),
        ).fetchone()

        if row:
            connection.execute(
                """
                UPDATE urls
                SET last_seen = ?
                WHERE id = ?
                """,
                (
                    timestamp,
                    row["id"],
                ),
            )

            connection.commit()

            return row["id"]

        cursor = connection.execute(
            """
            INSERT INTO urls (
                asset_id,
                url,
                normalized_url,
                scheme,
                port,
                path,
                query,
                first_seen,
                last_seen
            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                asset_id,
                normalized,
                normalized,
                parts.scheme,
                parts.port,
                parts.path or "/",
                parts.query,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

        return cursor.lastrowid

    finally:
        connection.close()
