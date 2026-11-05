from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from reconmancer.core.database import (
    connect,
)


SOURCE_TABLES = {
    "httpx": "http_observations",
    "katana": "katana_observations",
    "nuclei": "nuclei_findings",
}


VALID_ENGINES = {
    "httpx",
    "katana",
    "nuclei",
}


VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}


VALID_STATUSES = {
    "draft",
    "triage",
    "confirmed",
    "reported",
    "resolved",
    "duplicate",
    "not-applicable",
}


SENSITIVE_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
}


HEADER_RE = re.compile(
    r"(?im)^("
    r"authorization|"
    r"proxy-authorization|"
    r"cookie|"
    r"set-cookie|"
    r"x-api-key|"
    r"x-auth-token|"
    r"x-access-token|"
    r"x-csrf-token|"
    r"x-xsrf-token"
    r")\s*:[^\r\n]*"
)


def now_iso() -> str:

    return datetime.now(timezone.utc).isoformat()


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


def table_exists(
    connection,
    table: str,
) -> bool:

    row = connection.execute(
        """
        SELECT
            1

        FROM sqlite_master

        WHERE
            type = 'table'
            AND name = ?

        LIMIT 1
        """,
        (table,),
    ).fetchone()

    return row is not None


def table_columns(
    connection,
    table: str,
) -> set[str]:

    if not table_exists(
        connection,
        table,
    ):
        return set()

    rows = connection.execute(
        f"""
        PRAGMA table_info(
            {quote_identifier(table)}
        )
        """
    ).fetchall()

    return {row["name"] for row in rows}


def ensure_findings_schema(
    db_path: Path,
) -> None:

    connection = connect(db_path)

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS investigation_pins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                source_engine TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                source_record_id INTEGER NOT NULL,

                host TEXT,
                url TEXT,
                title TEXT,
                summary TEXT,
                severity TEXT,
                context TEXT,

                created_at TEXT NOT NULL,

                UNIQUE (
                    source_engine,
                    source_run_id,
                    source_record_id
                )
            );


            CREATE INDEX IF NOT EXISTS
                idx_investigation_pins_source
            ON investigation_pins (
                source_engine,
                source_run_id
            );


            CREATE INDEX IF NOT EXISTS
                idx_investigation_pins_host
            ON investigation_pins (
                host
            );


            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,

                title TEXT NOT NULL,

                status TEXT NOT NULL,
                severity TEXT NOT NULL,

                host TEXT,
                url TEXT,

                description TEXT,
                reproduction TEXT,
                impact TEXT,
                remediation TEXT,

                archived INTEGER NOT NULL DEFAULT 0,

                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );


            CREATE INDEX IF NOT EXISTS
                idx_findings_status
            ON findings (
                status
            );


            CREATE INDEX IF NOT EXISTS
                idx_findings_severity
            ON findings (
                severity
            );


            CREATE INDEX IF NOT EXISTS
                idx_findings_host
            ON findings (
                host
            );


            CREATE TABLE IF NOT EXISTS finding_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                finding_id TEXT NOT NULL,

                source_engine TEXT NOT NULL,
                source_run_id TEXT NOT NULL,
                source_record_id INTEGER NOT NULL,

                host TEXT,
                url TEXT,
                label TEXT,

                created_at TEXT NOT NULL,

                FOREIGN KEY (
                    finding_id
                )
                REFERENCES findings (
                    id
                )
                ON DELETE CASCADE,

                UNIQUE (
                    finding_id,
                    source_engine,
                    source_run_id,
                    source_record_id
                )
            );


            CREATE INDEX IF NOT EXISTS
                idx_finding_sources_finding
            ON finding_sources (
                finding_id
            );


            CREATE TABLE IF NOT EXISTS finding_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                finding_id TEXT NOT NULL,
                body TEXT NOT NULL,

                created_at TEXT NOT NULL,

                FOREIGN KEY (
                    finding_id
                )
                REFERENCES findings (
                    id
                )
                ON DELETE CASCADE
            );


            CREATE INDEX IF NOT EXISTS
                idx_finding_notes_finding
            ON finding_notes (
                finding_id
            );


            CREATE TABLE IF NOT EXISTS finding_tags (
                finding_id TEXT NOT NULL,
                tag TEXT NOT NULL,

                created_at TEXT NOT NULL,

                FOREIGN KEY (
                    finding_id
                )
                REFERENCES findings (
                    id
                )
                ON DELETE CASCADE,

                PRIMARY KEY (
                    finding_id,
                    tag
                )
            );


            CREATE TABLE IF NOT EXISTS finding_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                finding_id TEXT NOT NULL,

                evidence_hash TEXT NOT NULL,

                kind TEXT NOT NULL,
                label TEXT,

                relative_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,

                source_engine TEXT,
                source_run_id TEXT,
                source_record_id INTEGER,

                created_at TEXT NOT NULL,

                FOREIGN KEY (
                    finding_id
                )
                REFERENCES findings (
                    id
                )
                ON DELETE CASCADE,

                UNIQUE (
                    finding_id,
                    evidence_hash
                )
            );


            CREATE INDEX IF NOT EXISTS
                idx_finding_evidence_finding
            ON finding_evidence (
                finding_id
            );


            CREATE INDEX IF NOT EXISTS
                idx_finding_evidence_hash
            ON finding_evidence (
                evidence_hash
            );
            """
        )

        connection.commit()

    finally:
        connection.close()


def first_value(
    row: dict,
    names: tuple[str, ...],
):

    for name in names:
        value = row.get(name)

        if value is None:
            continue

        if isinstance(
            value,
            str,
        ):
            value = value.strip()

            if not value:
                continue

        return value

    return None


def hostname_from_url(
    value: str | None,
) -> str | None:

    if not value:
        return None

    try:
        parsed = urlsplit(value if "://" in value else "//" + value)

    except ValueError:
        return None

    host = parsed.hostname

    if not host:
        return None

    return host.lower().rstrip(".")


def get_run_context(
    connection,
    run_id: str,
) -> str:

    if not table_exists(
        connection,
        "runs",
    ):
        return "anonymous"

    row = connection.execute(
        """
        SELECT
            context

        FROM runs

        WHERE id = ?
        """,
        (run_id,),
    ).fetchone()

    if row is None:
        return "anonymous"

    return row["context"] or "anonymous"


def resolve_httpx_url(
    connection,
    row: dict,
) -> str | None:

    url_id = row.get("url_id")

    if url_id is None or not table_exists(
        connection,
        "urls",
    ):
        return first_value(
            row,
            (
                "normalized_url",
                "url",
            ),
        )

    url_row = connection.execute(
        """
        SELECT *
        FROM urls
        WHERE id = ?
        """,
        (url_id,),
    ).fetchone()

    if url_row is None:
        return None

    data = dict(url_row)

    return first_value(
        data,
        (
            "normalized_url",
            "url",
            "raw_url",
            "value",
        ),
    )


def source_summary(
    engine: str,
    row: dict,
) -> str:

    if engine == "httpx":
        parts = []

        status = row.get("status_code")

        method = row.get("method")

        title = row.get("title")

        server = row.get("server")

        if method:
            parts.append(str(method))

        if status is not None:
            parts.append(str(status))

        if title:
            parts.append(str(title))

        if server:
            parts.append(str(server))

        return " · ".join(parts) or "HTTP observation"

    if engine == "katana":
        parts = [
            value
            for value in (
                row.get("method"),
                row.get("status_code"),
                row.get("source_kind"),
                row.get("tag"),
            )
            if value
            not in (
                None,
                "",
            )
        ]

        return " · ".join(str(value) for value in parts) or "Katana discovery"

    parts = [
        value
        for value in (
            row.get("severity"),
            row.get("template_id"),
            row.get("matcher_name"),
        )
        if value
        not in (
            None,
            "",
        )
    ]

    return " · ".join(str(value) for value in parts) or "Nuclei finding"


def normalize_source_row(
    connection,
    engine: str,
    row: dict,
) -> dict:

    run_id = str(row.get("run_id") or "")

    if engine == "httpx":
        url = resolve_httpx_url(
            connection,
            row,
        )

        host = hostname_from_url(url) or first_value(
            row,
            (
                "host",
                "hostname",
            ),
        )

        title = row.get("title") or (
            f"HTTP {row.get('status_code')}"
            if row.get("status_code") is not None
            else "HTTP observation"
        )

        severity = "info"

    elif engine == "katana":
        url = first_value(
            row,
            (
                "normalized_url",
                "url",
            ),
        )

        host = first_value(
            row,
            (
                "host",
                "hostname",
            ),
        ) or hostname_from_url(url)

        title = row.get("source_kind") or row.get("tag") or "Katana discovery"

        severity = "info"

    else:
        url = first_value(
            row,
            (
                "matched_at",
                "url",
                "host",
            ),
        )

        host = first_value(
            row,
            ("host",),
        ) or hostname_from_url(url)

        title = row.get("name") or row.get("template_id") or "Nuclei finding"

        severity = str(row.get("severity") or "info").lower()

    context = row.get("context") or get_run_context(
        connection,
        run_id,
    )

    return {
        "engine": engine,
        "run_id": run_id,
        "record_id": int(row["id"]),
        "host": (str(host) if host else None),
        "url": (str(url) if url else None),
        "title": str(title),
        "summary": (
            source_summary(
                engine,
                row,
            )
        ),
        "severity": (severity if severity in VALID_SEVERITIES else "info"),
        "context": str(context or "anonymous"),
        "created_at": (row.get("created_at") or row.get("timestamp")),
        "raw": row,
    }


def get_source_record(
    db_path: Path,
    engine: str,
    run_id: str,
    record_id: int,
) -> dict | None:

    if engine not in VALID_ENGINES:
        return None

    table = SOURCE_TABLES[engine]

    connection = connect(db_path)

    try:
        if not table_exists(
            connection,
            table,
        ):
            return None

        columns = table_columns(
            connection,
            table,
        )

        if not {
            "id",
            "run_id",
        }.issubset(columns):
            return None

        row = connection.execute(
            f"""
            SELECT *
            FROM {quote_identifier(table)}
            WHERE
                id = ?
                AND run_id = ?
            """,
            (
                record_id,
                run_id,
            ),
        ).fetchone()

        if row is None:
            return None

        return normalize_source_row(
            connection,
            engine,
            dict(row),
        )

    finally:
        connection.close()


def recent_engine_rows(
    connection,
    engine: str,
    limit: int,
) -> list[dict]:

    table = SOURCE_TABLES[engine]

    if not table_exists(
        connection,
        table,
    ):
        return []

    columns = table_columns(
        connection,
        table,
    )

    if not {
        "id",
        "run_id",
    }.issubset(columns):
        return []

    order_column = (
        "created_at"
        if "created_at" in columns
        else ("timestamp" if "timestamp" in columns else "id")
    )

    rows = connection.execute(
        f"""
        SELECT *
        FROM {quote_identifier(table)}
        ORDER BY
            {quote_identifier(order_column)} DESC,
            id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [
        normalize_source_row(
            connection,
            engine,
            dict(row),
        )
        for row in rows
    ]


def source_matches_query(
    source: dict,
    query: str,
) -> bool:

    if not query:
        return True

    haystack = " ".join(
        str(source.get(key) or "")
        for key in (
            "engine",
            "run_id",
            "host",
            "url",
            "title",
            "summary",
            "severity",
            "context",
        )
    ).lower()

    return query.lower() in haystack


def list_recent_sources(
    db_path: Path,
    *,
    engine: str = "all",
    query: str = "",
    limit: int = 100,
) -> list[dict]:

    connection = connect(db_path)

    try:
        engines = list(VALID_ENGINES) if engine == "all" else [engine]

        items = []

        for current in engines:
            if current not in VALID_ENGINES:
                continue

            items.extend(
                recent_engine_rows(
                    connection,
                    current,
                    max(
                        limit,
                        100,
                    ),
                )
            )

    finally:
        connection.close()

    items = [
        item
        for item in items
        if source_matches_query(
            item,
            query,
        )
    ]

    items.sort(
        key=lambda item: (
            item.get("created_at") or "",
            item.get("record_id") or 0,
        ),
        reverse=True,
    )

    return items[:limit]


def build_correlations(
    sources: list[dict],
) -> list[dict]:

    groups = {}

    for source in sources:
        host = source.get("host") or "(unknown)"

        item = groups.setdefault(
            host,
            {
                "host": host,
                "httpx": 0,
                "katana": 0,
                "nuclei": 0,
                "critical": 0,
                "high": 0,
                "latest": None,
                "sample_url": (source.get("url")),
            },
        )

        engine = source["engine"]

        item[engine] += 1

        severity = source.get("severity")

        if severity in {
            "critical",
            "high",
        }:
            item[severity] += 1

        created = source.get("created_at")

        if created and (item["latest"] is None or created > item["latest"]):
            item["latest"] = created

    output = list(groups.values())

    output.sort(
        key=lambda item: (
            item["critical"],
            item["high"],
            item["nuclei"],
            item["httpx"] + item["katana"] + item["nuclei"],
        ),
        reverse=True,
    )

    return output[:100]


def pin_source(
    db_path: Path,
    engine: str,
    run_id: str,
    record_id: int,
) -> int:

    ensure_findings_schema(db_path)

    source = get_source_record(
        db_path,
        engine,
        run_id,
        record_id,
    )

    if source is None:
        raise ValueError("Source record does not exist.")

    connection = connect(db_path)

    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO
                investigation_pins (
                    source_engine,
                    source_run_id,
                    source_record_id,

                    host,
                    url,
                    title,
                    summary,
                    severity,
                    context,

                    created_at
                )

            VALUES (
                ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?
            )
            """,
            (
                source["engine"],
                source["run_id"],
                source["record_id"],
                source["host"],
                source["url"],
                source["title"],
                source["summary"],
                source["severity"],
                source["context"],
                now_iso(),
            ),
        )

        row = connection.execute(
            """
            SELECT id
            FROM investigation_pins

            WHERE
                source_engine = ?
                AND source_run_id = ?
                AND source_record_id = ?
            """,
            (
                engine,
                run_id,
                record_id,
            ),
        ).fetchone()

        connection.commit()

        return int(row["id"])

    finally:
        connection.close()


def unpin_source(
    db_path: Path,
    pin_id: int,
) -> None:

    connection = connect(db_path)

    try:
        connection.execute(
            """
            DELETE FROM investigation_pins
            WHERE id = ?
            """,
            (pin_id,),
        )

        connection.commit()

    finally:
        connection.close()


def list_pins(
    db_path: Path,
    *,
    limit: int = 200,
) -> list[dict]:

    ensure_findings_schema(db_path)

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM investigation_pins
            ORDER BY
                created_at DESC,
                id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def next_finding_id(
    connection,
) -> str:

    rows = connection.execute(
        """
        SELECT id
        FROM findings
        WHERE id LIKE 'F-%'
        """
    ).fetchall()

    highest = 0

    for row in rows:
        value = str(row["id"])

        try:
            number = int(
                value.split(
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

    return f"F-{highest + 1:04d}"


def clean_severity(
    value: str,
) -> str:

    value = value.strip().lower()

    if value not in VALID_SEVERITIES:
        return "info"

    return value


def clean_status(
    value: str,
) -> str:

    value = value.strip().lower()

    if value not in VALID_STATUSES:
        return "draft"

    return value


def create_finding(
    db_path: Path,
    *,
    title: str,
    severity: str,
    status: str,
    host: str,
    url: str,
    description: str,
    reproduction: str,
    impact: str,
    remediation: str,
    pin_ids: list[int],
) -> str:

    ensure_findings_schema(db_path)

    title = title.strip()

    if not title:
        raise ValueError("Finding title is required.")

    connection = connect(db_path)

    try:
        finding_id = next_finding_id(connection)

        timestamp = now_iso()

        connection.execute(
            """
            INSERT INTO findings (
                id,
                title,
                status,
                severity,
                host,
                url,
                description,
                reproduction,
                impact,
                remediation,
                archived,
                created_at,
                updated_at
            )

            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                0, ?, ?
            )
            """,
            (
                finding_id,
                title,
                clean_status(status),
                clean_severity(severity),
                host.strip() or None,
                url.strip() or None,
                description.strip(),
                reproduction.strip(),
                impact.strip(),
                remediation.strip(),
                timestamp,
                timestamp,
            ),
        )

        for pin_id in pin_ids:
            pin = connection.execute(
                """
                SELECT *
                FROM investigation_pins
                WHERE id = ?
                """,
                (pin_id,),
            ).fetchone()

            if pin is None:
                continue

            pin = dict(pin)

            connection.execute(
                """
                INSERT OR IGNORE INTO
                    finding_sources (
                        finding_id,

                        source_engine,
                        source_run_id,
                        source_record_id,

                        host,
                        url,
                        label,

                        created_at
                    )

                VALUES (
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?
                )
                """,
                (
                    finding_id,
                    pin["source_engine"],
                    pin["source_run_id"],
                    pin["source_record_id"],
                    pin["host"],
                    pin["url"],
                    pin["summary"],
                    timestamp,
                ),
            )

        connection.commit()

        return finding_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def list_findings(
    db_path: Path,
    *,
    include_archived: bool = False,
    limit: int = 300,
) -> list[dict]:

    ensure_findings_schema(db_path)

    connection = connect(db_path)

    try:
        where = ""

        if not include_archived:
            where = "WHERE f.archived = 0"

        rows = connection.execute(
            f"""
            SELECT
                f.*,

                (
                    SELECT COUNT(*)
                    FROM finding_sources fs
                    WHERE fs.finding_id = f.id
                ) AS source_count,

                (
                    SELECT COUNT(*)
                    FROM finding_evidence fe
                    WHERE fe.finding_id = f.id
                ) AS evidence_count,

                (
                    SELECT COUNT(*)
                    FROM finding_notes fn
                    WHERE fn.finding_id = f.id
                ) AS note_count

            FROM findings f

            {where}

            ORDER BY
                f.updated_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_finding(
    db_path: Path,
    finding_id: str,
) -> dict | None:

    ensure_findings_schema(db_path)

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT *
            FROM findings
            WHERE id = ?
            """,
            (finding_id,),
        ).fetchone()

        if row is None:
            return None

        finding = dict(row)

        finding["sources"] = [
            dict(item)
            for item in connection.execute(
                """
                SELECT *
                FROM finding_sources
                WHERE finding_id = ?
                ORDER BY
                    created_at DESC,
                    id DESC
                """,
                (finding_id,),
            ).fetchall()
        ]

        finding["notes"] = [
            dict(item)
            for item in connection.execute(
                """
                SELECT *
                FROM finding_notes
                WHERE finding_id = ?
                ORDER BY
                    created_at DESC,
                    id DESC
                """,
                (finding_id,),
            ).fetchall()
        ]

        finding["tags"] = [
            item["tag"]
            for item in connection.execute(
                """
                SELECT tag
                FROM finding_tags
                WHERE finding_id = ?
                ORDER BY tag
                """,
                (finding_id,),
            ).fetchall()
        ]

        finding["evidence"] = [
            dict(item)
            for item in connection.execute(
                """
                SELECT *
                FROM finding_evidence
                WHERE finding_id = ?
                ORDER BY
                    created_at DESC,
                    id DESC
                """,
                (finding_id,),
            ).fetchall()
        ]

        return finding

    finally:
        connection.close()


def update_finding(
    db_path: Path,
    finding_id: str,
    *,
    title: str,
    severity: str,
    status: str,
    host: str,
    url: str,
    description: str,
    reproduction: str,
    impact: str,
    remediation: str,
) -> None:

    connection = connect(db_path)

    try:
        cursor = connection.execute(
            """
            UPDATE findings

            SET
                title = ?,
                severity = ?,
                status = ?,
                host = ?,
                url = ?,
                description = ?,
                reproduction = ?,
                impact = ?,
                remediation = ?,
                updated_at = ?

            WHERE id = ?
            """,
            (
                title.strip(),
                clean_severity(severity),
                clean_status(status),
                host.strip() or None,
                url.strip() or None,
                description.strip(),
                reproduction.strip(),
                impact.strip(),
                remediation.strip(),
                now_iso(),
                finding_id,
            ),
        )

        if cursor.rowcount != 1:
            raise ValueError("Finding does not exist.")

        connection.commit()

    finally:
        connection.close()


def set_finding_archived(
    db_path: Path,
    finding_id: str,
    archived: bool,
) -> None:

    connection = connect(db_path)

    try:
        cursor = connection.execute(
            """
            UPDATE findings

            SET
                archived = ?,
                updated_at = ?

            WHERE id = ?
            """,
            (
                1 if archived else 0,
                now_iso(),
                finding_id,
            ),
        )

        if cursor.rowcount != 1:
            raise ValueError("Finding does not exist.")

        connection.commit()

    finally:
        connection.close()


def add_note(
    db_path: Path,
    finding_id: str,
    body: str,
) -> None:

    body = body.strip()

    if not body:
        raise ValueError("Note cannot be empty.")

    connection = connect(db_path)

    try:
        connection.execute(
            """
            INSERT INTO finding_notes (
                finding_id,
                body,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                finding_id,
                body,
                now_iso(),
            ),
        )

        connection.execute(
            """
            UPDATE findings
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now_iso(),
                finding_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def clean_tag(
    tag: str,
) -> str:

    tag = tag.strip().lower()

    tag = re.sub(
        r"[^a-z0-9._:-]+",
        "-",
        tag,
    )

    return tag[:64].strip("-")


def add_tag(
    db_path: Path,
    finding_id: str,
    tag: str,
) -> None:

    tag = clean_tag(tag)

    if not tag:
        raise ValueError("Tag is empty.")

    connection = connect(db_path)

    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO finding_tags (
                finding_id,
                tag,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                finding_id,
                tag,
                now_iso(),
            ),
        )

        connection.execute(
            """
            UPDATE findings
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now_iso(),
                finding_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def remove_tag(
    db_path: Path,
    finding_id: str,
    tag: str,
) -> None:

    connection = connect(db_path)

    try:
        connection.execute(
            """
            DELETE FROM finding_tags

            WHERE
                finding_id = ?
                AND tag = ?
            """,
            (
                finding_id,
                tag,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def attach_pin_to_finding(
    db_path: Path,
    finding_id: str,
    pin_id: int,
) -> None:

    connection = connect(db_path)

    try:
        pin = connection.execute(
            """
            SELECT *
            FROM investigation_pins
            WHERE id = ?
            """,
            (pin_id,),
        ).fetchone()

        if pin is None:
            raise ValueError("Pinned source does not exist.")

        pin = dict(pin)

        connection.execute(
            """
            INSERT OR IGNORE INTO finding_sources (
                finding_id,
                source_engine,
                source_run_id,
                source_record_id,
                host,
                url,
                label,
                created_at
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                pin["source_engine"],
                pin["source_run_id"],
                pin["source_record_id"],
                pin["host"],
                pin["url"],
                pin["summary"],
                now_iso(),
            ),
        )

        connection.execute(
            """
            UPDATE findings
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now_iso(),
                finding_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def remove_finding_source(
    db_path: Path,
    finding_id: str,
    source_id: int,
) -> None:

    connection = connect(db_path)

    try:
        connection.execute(
            """
            DELETE FROM finding_sources

            WHERE
                id = ?
                AND finding_id = ?
            """,
            (
                source_id,
                finding_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def redact_value(
    value,
):

    if isinstance(
        value,
        dict,
    ):
        output = {}

        for (
            key,
            item,
        ) in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                output[key] = "<redacted>"

            else:
                output[key] = redact_value(item)

        return output

    if isinstance(
        value,
        list,
    ):
        return [redact_value(item) for item in value]

    if isinstance(
        value,
        str,
    ):
        return HEADER_RE.sub(
            r"\1: <redacted>",
            value,
        )

    return value


def register_object(
    connection,
    *,
    sha256: str,
    relative_path: str,
    size_bytes: int,
) -> None:

    if not table_exists(
        connection,
        "objects",
    ):
        return

    columns = table_columns(
        connection,
        "objects",
    )

    required = {
        "hash",
        "kind",
        "relative_path",
        "size_bytes",
        "created_at",
    }

    if not required.issubset(columns):
        return

    if "compression" in columns:
        connection.execute(
            """
            INSERT OR IGNORE INTO objects (
                hash,
                kind,
                relative_path,
                size_bytes,
                compression,
                created_at
            )

            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                sha256,
                "evidence",
                relative_path,
                size_bytes,
                None,
                now_iso(),
            ),
        )

    else:
        connection.execute(
            """
            INSERT OR IGNORE INTO objects (
                hash,
                kind,
                relative_path,
                size_bytes,
                created_at
            )

            VALUES (?, ?, ?, ?, ?)
            """,
            (
                sha256,
                "evidence",
                relative_path,
                size_bytes,
                now_iso(),
            ),
        )


def write_evidence_object(
    project_root: Path,
    content: bytes,
    extension: str,
) -> tuple[
    str,
    str,
    int,
]:

    sha256 = hashlib.sha256(content).hexdigest()

    directory = project_root / "objects" / "evidence" / sha256[:2]

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    extension = extension.strip(".")

    filename = sha256 + ("." + extension if extension else "")

    path = directory / filename

    if not path.exists():
        path.write_bytes(content)

    relative_path = str(path.relative_to(project_root))

    return (
        sha256,
        relative_path,
        len(content),
    )


def add_evidence_record(
    db_path: Path,
    *,
    finding_id: str,
    evidence_hash: str,
    kind: str,
    label: str,
    relative_path: str,
    size_bytes: int,
    source_engine: str | None = None,
    source_run_id: str | None = None,
    source_record_id: int | None = None,
) -> None:

    connection = connect(db_path)

    try:
        register_object(
            connection,
            sha256=evidence_hash,
            relative_path=(relative_path),
            size_bytes=(size_bytes),
        )

        connection.execute(
            """
            INSERT OR IGNORE INTO finding_evidence (
                finding_id,
                evidence_hash,
                kind,
                label,
                relative_path,
                size_bytes,
                source_engine,
                source_run_id,
                source_record_id,
                created_at
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                evidence_hash,
                kind,
                label.strip() or None,
                relative_path,
                size_bytes,
                source_engine,
                source_run_id,
                source_record_id,
                now_iso(),
            ),
        )

        connection.execute(
            """
            UPDATE findings
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now_iso(),
                finding_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()


def snapshot_source_as_evidence(
    db_path: Path,
    project_root: Path,
    finding_id: str,
    source_id: int,
) -> str:

    connection = connect(db_path)

    try:
        source_link = connection.execute(
            """
            SELECT *
            FROM finding_sources

            WHERE
                id = ?
                AND finding_id = ?
            """,
            (
                source_id,
                finding_id,
            ),
        ).fetchone()

    finally:
        connection.close()

    if source_link is None:
        raise ValueError("Finding source does not exist.")

    source_link = dict(source_link)

    source = get_source_record(
        db_path,
        source_link["source_engine"],
        source_link["source_run_id"],
        int(source_link["source_record_id"]),
    )

    if source is None:
        raise ValueError(("The original source record no longer exists."))

    snapshot = {
        "reconmancer_evidence": {
            "finding_id": finding_id,
            "captured_at": now_iso(),
            "source_engine": (source["engine"]),
            "source_run_id": (source["run_id"]),
            "source_record_id": (source["record_id"]),
            "host": (source["host"]),
            "url": (source["url"]),
            "context": (source["context"]),
        },
        "source_record": (source["raw"]),
    }

    sanitized = redact_value(snapshot)

    content = json.dumps(
        sanitized,
        indent=2,
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    (
        evidence_hash,
        relative_path,
        size_bytes,
    ) = write_evidence_object(
        project_root,
        content,
        "json",
    )

    add_evidence_record(
        db_path,
        finding_id=finding_id,
        evidence_hash=(evidence_hash),
        kind="source-snapshot",
        label=(
            f"{source['engine'].upper()} "
            f"{source['run_id']} "
            f"record {source['record_id']}"
        ),
        relative_path=(relative_path),
        size_bytes=(size_bytes),
        source_engine=(source["engine"]),
        source_run_id=(source["run_id"]),
        source_record_id=(source["record_id"]),
    )

    return evidence_hash


def add_manual_evidence(
    db_path: Path,
    project_root: Path,
    finding_id: str,
    *,
    label: str,
    body: str,
) -> str:

    body = body.strip()

    if not body:
        raise ValueError("Evidence body cannot be empty.")

    body = HEADER_RE.sub(
        r"\1: <redacted>",
        body,
    )

    content = body.encode("utf-8")

    (
        evidence_hash,
        relative_path,
        size_bytes,
    ) = write_evidence_object(
        project_root,
        content,
        "txt",
    )

    add_evidence_record(
        db_path,
        finding_id=finding_id,
        evidence_hash=(evidence_hash),
        kind="manual-text",
        label=(label),
        relative_path=(relative_path),
        size_bytes=(size_bytes),
    )

    return evidence_hash


def evidence_path(
    project_root: Path,
    finding: dict,
    evidence_id: int,
) -> Path | None:

    evidence = None

    for item in finding.get("evidence", []):
        if int(item["id"]) == int(evidence_id):
            evidence = item
            break

    if evidence is None:
        return None

    root = project_root.resolve()

    path = (project_root / evidence["relative_path"]).resolve()

    try:
        path.relative_to(root)

    except ValueError:
        return None

    if not path.is_file():
        return None

    return path


def workspace_counts(
    db_path: Path,
) -> dict:

    ensure_findings_schema(db_path)

    connection = connect(db_path)

    try:

        def count(
            query: str,
        ) -> int:

            row = connection.execute(query).fetchone()

            return int(row[0] or 0)

        return {
            "findings": count(
                """
                SELECT COUNT(*)
                FROM findings
                WHERE archived = 0
                """
            ),
            "pins": count(
                """
                SELECT COUNT(*)
                FROM investigation_pins
                """
            ),
            "evidence": count(
                """
                SELECT COUNT(*)
                FROM finding_evidence
                """
            ),
            "critical": count(
                """
                SELECT COUNT(*)
                FROM findings
                WHERE
                    archived = 0
                    AND severity = 'critical'
                """
            ),
            "high": count(
                """
                SELECT COUNT(*)
                FROM findings
                WHERE
                    archived = 0
                    AND severity = 'high'
                """
            ),
        }

    finally:
        connection.close()


def build_findings_workspace(
    db_path: Path,
    *,
    engine: str = "all",
    query: str = "",
) -> dict:

    ensure_findings_schema(db_path)

    sources = list_recent_sources(
        db_path,
        engine=engine,
        query=query,
        limit=120,
    )

    pins = list_pins(
        db_path,
        limit=200,
    )

    pinned_keys = {
        (
            pin["source_engine"],
            pin["source_run_id"],
            int(pin["source_record_id"]),
        )
        for pin in pins
    }

    for source in sources:
        source["pinned"] = (
            source["engine"],
            source["run_id"],
            int(source["record_id"]),
        ) in pinned_keys

    return {
        "counts": workspace_counts(db_path),
        "findings": list_findings(db_path),
        "pins": pins,
        "sources": sources,
        "correlations": (build_correlations(sources)),
        "engine_filter": engine,
        "query": query,
    }
