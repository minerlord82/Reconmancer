from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from reconmancer.core.database import connect


SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_url_state (
    url_id INTEGER PRIMARY KEY,
    analyzed_at TEXT NOT NULL,
    FOREIGN KEY(url_id) REFERENCES urls(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS endpoint_clusters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_key TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    scheme TEXT,
    port INTEGER,
    path_pattern TEXT NOT NULL,
    sample_url TEXT NOT NULL,
    url_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_endpoint_clusters_host
ON endpoint_clusters(host);

CREATE INDEX IF NOT EXISTS idx_endpoint_clusters_count
ON endpoint_clusters(url_count);

CREATE TABLE IF NOT EXISTS endpoint_cluster_members (
    cluster_id INTEGER NOT NULL,
    url_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(cluster_id, url_id),
    FOREIGN KEY(cluster_id) REFERENCES endpoint_clusters(id) ON DELETE CASCADE,
    FOREIGN KEY(url_id) REFERENCES urls(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS query_parameter_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_key TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    parameter_name TEXT NOT NULL,
    total_urls INTEGER NOT NULL DEFAULT 0,
    numeric_count INTEGER NOT NULL DEFAULT 0,
    uuid_count INTEGER NOT NULL DEFAULT 0,
    hex_count INTEGER NOT NULL DEFAULT 0,
    token_count INTEGER NOT NULL DEFAULT 0,
    url_value_count INTEGER NOT NULL DEFAULT 0,
    path_value_count INTEGER NOT NULL DEFAULT 0,
    empty_count INTEGER NOT NULL DEFAULT 0,
    id_like INTEGER NOT NULL DEFAULT 0,
    url_like INTEGER NOT NULL DEFAULT 0,
    file_like INTEGER NOT NULL DEFAULT 0,
    examples_json TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_query_parameter_name
ON query_parameter_stats(parameter_name);

CREATE INDEX IF NOT EXISTS idx_query_parameter_host
ON query_parameter_stats(host);

CREATE INDEX IF NOT EXISTS idx_query_parameter_flags
ON query_parameter_stats(id_like, url_like, file_like);

CREATE TABLE IF NOT EXISTS query_parameter_members (
    stat_id INTEGER NOT NULL,
    url_id INTEGER NOT NULL,
    value_shape TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    value_preview TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY(stat_id, url_id, value_hash),
    FOREIGN KEY(stat_id) REFERENCES query_parameter_stats(id) ON DELETE CASCADE,
    FOREIGN KEY(url_id) REFERENCES urls(id) ON DELETE CASCADE
);
"""


UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)
INT_RE = re.compile(r"^[0-9]+$")
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$", re.IGNORECASE)
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,}$")
DATE_RE = re.compile(r"^\d{4}[-_/]\d{1,2}[-_/]\d{1,2}$")

ID_NAME_RE = re.compile(
    r"(^id$|(^|_)(user|account|customer|merchant|shop|order|invoice|payment|"
    r"transaction|profile|member|object|document|ticket|record|item|uuid|guid)(_|$)|_id$)",
    re.IGNORECASE,
)
URL_NAME_RE = re.compile(
    r"(^|_)(url|uri|redirect|redirect_uri|next|return|return_to|callback|"
    r"continue|dest|destination|target|link)(_|$)",
    re.IGNORECASE,
)
FILE_NAME_RE = re.compile(
    r"(^|_)(file|filename|path|folder|directory|document|download|attachment)(_|$)",
    re.IGNORECASE,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_analysis_schema(db_path: Path) -> None:
    connection = connect(db_path)
    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()


def segment_pattern(segment: str) -> str:
    if not segment:
        return segment

    if UUID_RE.fullmatch(segment):
        return "{uuid}"

    if ULID_RE.fullmatch(segment):
        return "{ulid}"

    if INT_RE.fullmatch(segment):
        return "{int}"

    if DATE_RE.fullmatch(segment):
        return "{date}"

    if HEX_RE.fullmatch(segment):
        return "{hex}"

    if TOKEN_RE.fullmatch(segment):
        return "{token}"

    return segment


def endpoint_pattern(path: str) -> str:
    path = path or "/"
    pieces = path.split("/")
    transformed = [segment_pattern(piece) for piece in pieces]
    output = "/".join(transformed)
    return output or "/"


def value_shape(value: str) -> str:
    value = value.strip()

    if not value:
        return "empty"

    if UUID_RE.fullmatch(value):
        return "uuid"

    if ULID_RE.fullmatch(value):
        return "token"

    if INT_RE.fullmatch(value):
        return "numeric"

    if HEX_RE.fullmatch(value):
        return "hex"

    try:
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            return "url"
    except ValueError:
        pass

    if value.startswith(("/", "./", "../", "\\")):
        return "path"

    if TOKEN_RE.fullmatch(value):
        return "token"

    return "text"


def _cluster_key(host: str, scheme: str, port: int | None, pattern: str) -> str:
    material = f"{scheme}|{host}|{port or ''}|{pattern}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _stat_key(host: str, pattern: str, name: str) -> str:
    material = f"{host}|{pattern}|{name.lower()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _update_examples(current: str, value: str, limit: int = 5) -> str:
    try:
        examples = json.loads(current or "[]")
    except json.JSONDecodeError:
        examples = []

    if not isinstance(examples, list):
        examples = []

    preview = value[:160]

    if preview not in examples:
        examples.append(preview)

    return json.dumps(examples[:limit], ensure_ascii=False)


def refresh_url_analysis(
    db_path: Path,
    *,
    batch_size: int = 1000,
    max_batches: int = 100,
) -> dict:
    ensure_analysis_schema(db_path)

    processed = 0
    clusters_created = 0
    params_seen = 0

    connection = connect(db_path)
    try:
        for _ in range(max_batches):
            rows = connection.execute(
                """
                SELECT
                    u.id,
                    u.url,
                    u.normalized_url,
                    u.scheme,
                    u.port,
                    u.path,
                    u.query,
                    u.first_seen,
                    u.last_seen,
                    a.host
                FROM urls u
                LEFT JOIN assets a ON a.id = u.asset_id
                LEFT JOIN analysis_url_state s ON s.url_id = u.id
                WHERE s.url_id IS NULL
                ORDER BY u.id ASC
                LIMIT ?
                """,
                (batch_size,),
            ).fetchall()

            if not rows:
                break

            for row in rows:
                url_id = int(row["id"])
                raw_url = row["normalized_url"] or row["url"]

                try:
                    parsed = urlsplit(raw_url)
                except ValueError:
                    connection.execute(
                        "INSERT OR IGNORE INTO analysis_url_state(url_id, analyzed_at) VALUES (?, ?)",
                        (url_id, now_iso()),
                    )
                    continue

                host = (row["host"] or parsed.hostname or "").lower().rstrip(".")
                if not host:
                    connection.execute(
                        "INSERT OR IGNORE INTO analysis_url_state(url_id, analyzed_at) VALUES (?, ?)",
                        (url_id, now_iso()),
                    )
                    continue

                scheme = row["scheme"] or parsed.scheme or ""
                port = row["port"] or parsed.port
                path = row["path"] or parsed.path or "/"
                query = row["query"] if row["query"] is not None else parsed.query
                pattern = endpoint_pattern(path)
                timestamp = row["last_seen"] or row["first_seen"] or now_iso()
                key = _cluster_key(host, scheme, port, pattern)

                connection.execute(
                    """
                    INSERT INTO endpoint_clusters (
                        cluster_key, host, scheme, port, path_pattern,
                        sample_url, url_count, first_seen, last_seen
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                    ON CONFLICT(cluster_key)
                    DO UPDATE SET
                        last_seen = excluded.last_seen
                    """,
                    (
                        key,
                        host,
                        scheme,
                        port,
                        pattern,
                        raw_url,
                        row["first_seen"] or now_iso(),
                        timestamp,
                    ),
                )

                cluster_row = connection.execute(
                    "SELECT id FROM endpoint_clusters WHERE cluster_key = ?",
                    (key,),
                ).fetchone()
                cluster_id = int(cluster_row["id"])

                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO endpoint_cluster_members (
                        cluster_id, url_id, created_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (cluster_id, url_id, now_iso()),
                )

                if cursor.rowcount:
                    connection.execute(
                        """
                        UPDATE endpoint_clusters
                        SET url_count = url_count + 1,
                            last_seen = ?
                        WHERE id = ?
                        """,
                        (timestamp, cluster_id),
                    )
                    clusters_created += 1

                for name, value in parse_qsl(query or "", keep_blank_values=True):
                    clean_name = name.strip()
                    if not clean_name:
                        continue

                    shape = value_shape(value)
                    stat_key = _stat_key(host, pattern, clean_name)
                    id_like = bool(ID_NAME_RE.search(clean_name)) or shape in {
                        "numeric",
                        "uuid",
                        "hex",
                        "token",
                    }
                    url_like = bool(URL_NAME_RE.search(clean_name)) or shape == "url"
                    file_like = bool(FILE_NAME_RE.search(clean_name)) or shape == "path"

                    connection.execute(
                        """
                        INSERT INTO query_parameter_stats (
                            stat_key, host, path_pattern, parameter_name,
                            total_urls, id_like, url_like, file_like,
                            examples_json, first_seen, last_seen
                        )
                        VALUES (?, ?, ?, ?, 0, ?, ?, ?, '[]', ?, ?)
                        ON CONFLICT(stat_key)
                        DO UPDATE SET
                            id_like = MAX(query_parameter_stats.id_like, excluded.id_like),
                            url_like = MAX(query_parameter_stats.url_like, excluded.url_like),
                            file_like = MAX(query_parameter_stats.file_like, excluded.file_like),
                            last_seen = excluded.last_seen
                        """,
                        (
                            stat_key,
                            host,
                            pattern,
                            clean_name,
                            1 if id_like else 0,
                            1 if url_like else 0,
                            1 if file_like else 0,
                            row["first_seen"] or now_iso(),
                            timestamp,
                        ),
                    )

                    stat_row = connection.execute(
                        "SELECT id, examples_json FROM query_parameter_stats WHERE stat_key = ?",
                        (stat_key,),
                    ).fetchone()
                    stat_id = int(stat_row["id"])
                    value_hash = hashlib.sha256(
                        value.encode("utf-8", errors="replace")
                    ).hexdigest()

                    cursor = connection.execute(
                        """
                        INSERT OR IGNORE INTO query_parameter_members (
                            stat_id, url_id, value_shape, value_hash,
                            value_preview, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            stat_id,
                            url_id,
                            shape,
                            value_hash,
                            value[:160],
                            now_iso(),
                        ),
                    )

                    if cursor.rowcount:
                        count_column = {
                            "numeric": "numeric_count",
                            "uuid": "uuid_count",
                            "hex": "hex_count",
                            "token": "token_count",
                            "url": "url_value_count",
                            "path": "path_value_count",
                            "empty": "empty_count",
                        }.get(shape)

                        if count_column:
                            connection.execute(
                                f"""
                                UPDATE query_parameter_stats
                                SET total_urls = total_urls + 1,
                                    {count_column} = {count_column} + 1,
                                    examples_json = ?,
                                    last_seen = ?
                                WHERE id = ?
                                """,
                                (
                                    _update_examples(stat_row["examples_json"], value),
                                    timestamp,
                                    stat_id,
                                ),
                            )
                        else:
                            connection.execute(
                                """
                                UPDATE query_parameter_stats
                                SET total_urls = total_urls + 1,
                                    examples_json = ?,
                                    last_seen = ?
                                WHERE id = ?
                                """,
                                (
                                    _update_examples(stat_row["examples_json"], value),
                                    timestamp,
                                    stat_id,
                                ),
                            )
                        params_seen += 1

                connection.execute(
                    "INSERT OR IGNORE INTO analysis_url_state(url_id, analyzed_at) VALUES (?, ?)",
                    (url_id, now_iso()),
                )
                processed += 1

            connection.commit()

            if len(rows) < batch_size:
                break

        return {
            "processed_urls": processed,
            "cluster_members_added": clusters_created,
            "parameter_values_added": params_seen,
        }
    finally:
        connection.close()


def list_endpoint_clusters(
    db_path: Path,
    *,
    query: str = "",
    minimum_variants: int = 2,
    page: int = 1,
    per_page: int = 100,
) -> dict:
    ensure_analysis_schema(db_path)
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 250))
    minimum_variants = max(1, int(minimum_variants))

    where = ["url_count >= ?"]
    params: list[object] = [minimum_variants]

    if query:
        like = f"%{query}%"
        where.append("(host LIKE ? OR path_pattern LIKE ? OR sample_url LIKE ?)")
        params.extend([like, like, like])

    where_sql = "WHERE " + " AND ".join(where)

    connection = connect(db_path)
    try:
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM endpoint_clusters {where_sql}",
                params,
            ).fetchone()[0]
        )
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)

        rows = connection.execute(
            f"""
            SELECT *
            FROM endpoint_clusters
            {where_sql}
            ORDER BY url_count DESC, last_seen DESC
            LIMIT ? OFFSET ?
            """,
            [*params, per_page, (page - 1) * per_page],
        ).fetchall()

        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "page": page,
            "pages": pages,
        }
    finally:
        connection.close()


def list_query_parameters(
    db_path: Path,
    *,
    query: str = "",
    kind: str = "all",
    page: int = 1,
    per_page: int = 100,
) -> dict:
    ensure_analysis_schema(db_path)
    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 250))

    where = []
    params: list[object] = []

    if kind == "id-like":
        where.append("id_like = 1")
    elif kind == "url-like":
        where.append("url_like = 1")
    elif kind == "file-like":
        where.append("file_like = 1")

    if query:
        like = f"%{query}%"
        where.append("(host LIKE ? OR path_pattern LIKE ? OR parameter_name LIKE ?)")
        params.extend([like, like, like])

    where_sql = ""
    if where:
        where_sql = "WHERE " + " AND ".join(where)

    connection = connect(db_path)
    try:
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM query_parameter_stats {where_sql}",
                params,
            ).fetchone()[0]
        )
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)

        rows = connection.execute(
            f"""
            SELECT *
            FROM query_parameter_stats
            {where_sql}
            ORDER BY
                id_like DESC,
                url_like DESC,
                file_like DESC,
                total_urls DESC,
                last_seen DESC
            LIMIT ? OFFSET ?
            """,
            [*params, per_page, (page - 1) * per_page],
        ).fetchall()

        items = []
        for row in rows:
            item = dict(row)
            try:
                item["examples"] = json.loads(item.get("examples_json") or "[]")
            except json.JSONDecodeError:
                item["examples"] = []
            items.append(item)

        return {
            "items": items,
            "total": total,
            "page": page,
            "pages": pages,
        }
    finally:
        connection.close()
