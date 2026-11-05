from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;


CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);


INSERT INTO schema_info(version)
SELECT 1
WHERE NOT EXISTS (
    SELECT 1
    FROM schema_info
);


CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,

    engine TEXT NOT NULL,
    profile TEXT,

    context TEXT NOT NULL
        DEFAULT 'anonymous',

    status TEXT NOT NULL,

    started_at TEXT,
    finished_at TEXT,

    input_count INTEGER NOT NULL
        DEFAULT 0,

    result_count INTEGER NOT NULL
        DEFAULT 0,

    command_json TEXT,

    error TEXT
);


CREATE INDEX IF NOT EXISTS idx_runs_engine
ON runs(engine);


CREATE INDEX IF NOT EXISTS idx_runs_status
ON runs(status);


CREATE INDEX IF NOT EXISTS idx_runs_started
ON runs(started_at);


CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,

    engine TEXT NOT NULL,

    status TEXT NOT NULL,

    created_at TEXT NOT NULL,

    started_at TEXT,
    finished_at TEXT,

    payload_json TEXT,

    run_id TEXT,

    FOREIGN KEY(run_id)
        REFERENCES runs(id)
        ON DELETE SET NULL
);


CREATE INDEX IF NOT EXISTS idx_jobs_engine
ON jobs(engine);


CREATE INDEX IF NOT EXISTS idx_jobs_status
ON jobs(status);


CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    host TEXT NOT NULL UNIQUE,

    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);


CREATE INDEX IF NOT EXISTS idx_assets_host
ON assets(host);


CREATE INDEX IF NOT EXISTS idx_assets_last_seen
ON assets(last_seen);


CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    asset_id INTEGER,

    url TEXT NOT NULL UNIQUE,

    normalized_url TEXT NOT NULL,

    scheme TEXT,

    port INTEGER,

    path TEXT,

    query TEXT,

    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,

    FOREIGN KEY(asset_id)
        REFERENCES assets(id)
        ON DELETE SET NULL
);


CREATE INDEX IF NOT EXISTS idx_urls_asset
ON urls(asset_id);


CREATE INDEX IF NOT EXISTS idx_urls_normalized
ON urls(normalized_url);


CREATE INDEX IF NOT EXISTS idx_urls_scheme
ON urls(scheme);


CREATE INDEX IF NOT EXISTS idx_urls_last_seen
ON urls(last_seen);


CREATE TABLE IF NOT EXISTS http_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    run_id TEXT NOT NULL,

    url_id INTEGER NOT NULL,

    context TEXT NOT NULL
        DEFAULT 'anonymous',

    status_code INTEGER,

    title TEXT,

    content_type TEXT,

    content_length INTEGER,

    line_count INTEGER,

    word_count INTEGER,

    response_time_ms REAL,

    method TEXT,

    server TEXT,

    technologies_json TEXT,

    ip TEXT,

    cname TEXT,

    asn TEXT,

    cdn TEXT,

    cdn_name TEXT,

    cdn_type TEXT,

    redirect_location TEXT,

    body_hash TEXT,

    header_hash TEXT,

    favicon_hash TEXT,

    jarm TEXT,

    tls_json TEXT,

    http2 INTEGER,

    websocket INTEGER,

    screenshot_hash TEXT,

    created_at TEXT NOT NULL,

    FOREIGN KEY(run_id)
        REFERENCES runs(id)
        ON DELETE CASCADE,

    FOREIGN KEY(url_id)
        REFERENCES urls(id)
        ON DELETE CASCADE
);


CREATE INDEX IF NOT EXISTS idx_http_obs_url
ON http_observations(url_id);


CREATE INDEX IF NOT EXISTS idx_http_obs_run
ON http_observations(run_id);


CREATE INDEX IF NOT EXISTS idx_http_obs_status
ON http_observations(status_code);


CREATE INDEX IF NOT EXISTS idx_http_obs_context
ON http_observations(context);


CREATE INDEX IF NOT EXISTS idx_http_obs_ip
ON http_observations(ip);


CREATE INDEX IF NOT EXISTS idx_http_obs_cdn_name
ON http_observations(cdn_name);


CREATE INDEX IF NOT EXISTS idx_http_obs_created
ON http_observations(created_at);


CREATE TABLE IF NOT EXISTS redirects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    run_id TEXT NOT NULL,

    source_url_id INTEGER NOT NULL,

    status_code INTEGER,

    destination_url TEXT NOT NULL,

    destination_url_id INTEGER,

    depth INTEGER NOT NULL
        DEFAULT 0,

    context TEXT NOT NULL
        DEFAULT 'anonymous',

    created_at TEXT NOT NULL,

    FOREIGN KEY(run_id)
        REFERENCES runs(id)
        ON DELETE CASCADE,

    FOREIGN KEY(source_url_id)
        REFERENCES urls(id)
        ON DELETE CASCADE,

    FOREIGN KEY(destination_url_id)
        REFERENCES urls(id)
        ON DELETE SET NULL
);


CREATE INDEX IF NOT EXISTS idx_redirect_source
ON redirects(source_url_id);


CREATE INDEX IF NOT EXISTS idx_redirect_destination
ON redirects(destination_url);


CREATE INDEX IF NOT EXISTS idx_redirect_run
ON redirects(run_id);


CREATE INDEX IF NOT EXISTS idx_redirect_context
ON redirects(context);


CREATE INDEX IF NOT EXISTS idx_redirect_depth
ON redirects(depth);


CREATE TABLE IF NOT EXISTS discoveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    run_id TEXT,

    source_url_id INTEGER,

    engine TEXT NOT NULL,

    kind TEXT NOT NULL,

    value TEXT NOT NULL,

    normalized_value TEXT,

    context TEXT NOT NULL
        DEFAULT 'anonymous',

    created_at TEXT NOT NULL,

    FOREIGN KEY(run_id)
        REFERENCES runs(id)
        ON DELETE SET NULL,

    FOREIGN KEY(source_url_id)
        REFERENCES urls(id)
        ON DELETE SET NULL
);


CREATE INDEX IF NOT EXISTS idx_discoveries_kind
ON discoveries(kind);


CREATE INDEX IF NOT EXISTS idx_discoveries_value
ON discoveries(normalized_value);


CREATE INDEX IF NOT EXISTS idx_discoveries_engine
ON discoveries(engine);


CREATE INDEX IF NOT EXISTS idx_discoveries_run
ON discoveries(run_id);


CREATE TABLE IF NOT EXISTS objects (
    hash TEXT PRIMARY KEY,

    kind TEXT NOT NULL,

    relative_path TEXT NOT NULL,

    size_bytes INTEGER NOT NULL,

    compression TEXT,

    created_at TEXT NOT NULL
);


CREATE INDEX IF NOT EXISTS idx_objects_kind
ON objects(kind);


CREATE TABLE IF NOT EXISTS handoffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    source_engine TEXT NOT NULL,

    destination_engine TEXT NOT NULL,

    source_type TEXT NOT NULL,

    source_id TEXT NOT NULL,

    status TEXT NOT NULL
        DEFAULT 'queued',

    created_at TEXT NOT NULL,

    job_id TEXT,

    FOREIGN KEY(job_id)
        REFERENCES jobs(id)
        ON DELETE SET NULL
);


CREATE INDEX IF NOT EXISTS idx_handoffs_status
ON handoffs(status);


CREATE INDEX IF NOT EXISTS idx_handoffs_source_engine
ON handoffs(source_engine);


CREATE INDEX IF NOT EXISTS idx_handoffs_destination_engine
ON handoffs(destination_engine);


CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    name TEXT NOT NULL UNIQUE
);


CREATE TABLE IF NOT EXISTS asset_tags (
    asset_id INTEGER NOT NULL,

    tag_id INTEGER NOT NULL,

    PRIMARY KEY(
        asset_id,
        tag_id
    ),

    FOREIGN KEY(asset_id)
        REFERENCES assets(id)
        ON DELETE CASCADE,

    FOREIGN KEY(tag_id)
        REFERENCES tags(id)
        ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    object_type TEXT NOT NULL,

    object_id TEXT NOT NULL,

    body TEXT NOT NULL,

    created_at TEXT NOT NULL,

    updated_at TEXT NOT NULL
);


CREATE INDEX IF NOT EXISTS idx_notes_object
ON notes(
    object_type,
    object_id
);
"""


def connect(
    db_path: Path | str,
) -> sqlite3.Connection:

    db_path = Path(db_path)

    connection = sqlite3.connect(
        db_path,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    connection.execute("PRAGMA journal_mode = WAL")

    connection.execute("PRAGMA synchronous = NORMAL")

    connection.execute("PRAGMA temp_store = MEMORY")

    connection.execute("PRAGMA busy_timeout = 30000")

    return connection


def migrate_database(
    db_path: Path | str,
) -> None:

    db_path = Path(db_path)

    connection = connect(db_path)

    additions = [
        (
            "method",
            "TEXT",
        ),
        (
            "cdn_name",
            "TEXT",
        ),
        (
            "cdn_type",
            "TEXT",
        ),
        (
            "header_hash",
            "TEXT",
        ),
        (
            "tls_json",
            "TEXT",
        ),
    ]

    try:
        existing = {
            row["name"]
            for row in connection.execute(
                """
                PRAGMA table_info(
                    http_observations
                )
                """
            )
        }

        for (
            column_name,
            column_type,
        ) in additions:
            if column_name in existing:
                continue

            connection.execute(
                f"""
                ALTER TABLE
                    http_observations

                ADD COLUMN
                    {column_name}
                    {column_type}
                """
            )

        connection.commit()

    finally:
        connection.close()


def initialize_database(
    db_path: Path | str,
) -> None:

    db_path = Path(db_path)

    db_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = connect(db_path)

    try:
        connection.executescript(SCHEMA)

        connection.commit()

    finally:
        connection.close()

    migrate_database(db_path)


def get_counts(
    db_path: Path | str,
) -> dict:

    connection = connect(db_path)

    try:
        queries = {
            "assets": ("SELECT COUNT(*) FROM assets"),
            "urls": ("SELECT COUNT(*) FROM urls"),
            "redirects": ("SELECT COUNT(*) FROM redirects"),
            "discoveries": ("SELECT COUNT(*) FROM discoveries"),
            "runs": ("SELECT COUNT(*) FROM runs"),
        }

        counts = {}

        for (
            key,
            query,
        ) in queries.items():
            counts[key] = connection.execute(query).fetchone()[0]

        return counts

    finally:
        connection.close()
