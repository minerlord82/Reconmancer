from __future__ import annotations

from pathlib import Path
from urllib.parse import (
    parse_qsl,
    urlparse,
)

from reconmancer.core.database import connect


CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS katana_observations (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    run_id TEXT NOT NULL,

    profile TEXT NOT NULL
        DEFAULT 'standard',

    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,

    host TEXT,
    path TEXT,

    query_signature TEXT NOT NULL
        DEFAULT '',

    source_url TEXT,

    method TEXT,
    status_code INTEGER,

    content_type TEXT,

    tag TEXT,
    attribute TEXT,

    technologies_json TEXT,
    query_keys_json TEXT,

    is_javascript INTEGER NOT NULL
        DEFAULT 0,

    is_query INTEGER NOT NULL
        DEFAULT 0,

    is_xhr INTEGER NOT NULL
        DEFAULT 0,

    is_runtime INTEGER NOT NULL
        DEFAULT 0,

    source_kind TEXT,

    raw_json TEXT NOT NULL,

    created_at TEXT NOT NULL,

    FOREIGN KEY(run_id)
        REFERENCES runs(id)
        ON DELETE CASCADE
);
"""


INDEXES = """
CREATE INDEX IF NOT EXISTS
idx_katana_observations_run
ON katana_observations(run_id);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_url
ON katana_observations(normalized_url);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_status
ON katana_observations(status_code);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_profile
ON katana_observations(
    run_id,
    profile
);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_js
ON katana_observations(
    run_id,
    is_javascript
);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_query
ON katana_observations(
    run_id,
    is_query
);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_xhr
ON katana_observations(
    run_id,
    is_xhr
);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_runtime
ON katana_observations(
    run_id,
    is_runtime
);


CREATE INDEX IF NOT EXISTS
idx_katana_observations_group
ON katana_observations(
    run_id,
    host,
    path,
    query_signature
);
"""


MIGRATIONS = {
    "profile": """
        ALTER TABLE katana_observations
        ADD COLUMN profile TEXT
        NOT NULL DEFAULT 'standard'
    """,
    "host": """
        ALTER TABLE katana_observations
        ADD COLUMN host TEXT
    """,
    "path": """
        ALTER TABLE katana_observations
        ADD COLUMN path TEXT
    """,
    "query_signature": """
        ALTER TABLE katana_observations
        ADD COLUMN query_signature TEXT
        NOT NULL DEFAULT ''
    """,
    "is_xhr": """
        ALTER TABLE katana_observations
        ADD COLUMN is_xhr INTEGER
        NOT NULL DEFAULT 0
    """,
    "is_runtime": """
        ALTER TABLE katana_observations
        ADD COLUMN is_runtime INTEGER
        NOT NULL DEFAULT 0
    """,
    "source_kind": """
        ALTER TABLE katana_observations
        ADD COLUMN source_kind TEXT
    """,
}


def url_shape(
    value: str,
) -> tuple[
    str,
    str,
    str,
]:

    try:
        parsed = urlparse(value)

        host = (parsed.hostname or "").lower()

        path = parsed.path or "/"

        keys = sorted(
            {
                key
                for key, _ in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                )
            }
        )

        signature = "&".join(keys)

        return (
            host,
            path,
            signature,
        )

    except Exception:
        return (
            "",
            "",
            "",
        )


def migrate_columns(
    connection,
) -> None:

    columns = {
        row["name"]
        for row in connection.execute(
            """
            PRAGMA table_info(
                katana_observations
            )
            """
        ).fetchall()
    }

    for (
        column,
        statement,
    ) in MIGRATIONS.items():
        if column in columns:
            continue

        connection.execute(statement)


def backfill_url_shapes(
    connection,
) -> None:

    last_id = 0

    while True:
        rows = connection.execute(
            """
            SELECT
                id,
                normalized_url

            FROM katana_observations

            WHERE
                id > ?
                AND (
                    host IS NULL
                    OR path IS NULL
                )

            ORDER BY id ASC

            LIMIT 500
            """,
            (last_id,),
        ).fetchall()

        if not rows:
            break

        for row in rows:
            (
                host,
                path,
                signature,
            ) = url_shape(row["normalized_url"])

            connection.execute(
                """
                UPDATE katana_observations

                SET
                    host = ?,
                    path = ?,
                    query_signature = ?

                WHERE id = ?
                """,
                (
                    host,
                    path,
                    signature,
                    row["id"],
                ),
            )

        last_id = rows[-1]["id"]

        connection.commit()


def ensure_katana_schema(
    db_path: Path,
) -> None:

    connection = connect(db_path)

    try:
        connection.execute(CREATE_TABLE)

        migrate_columns(connection)

        connection.executescript(INDEXES)

        connection.commit()

        backfill_url_shapes(connection)

        connection.commit()

    finally:
        connection.close()
