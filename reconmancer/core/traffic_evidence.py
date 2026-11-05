from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reconmancer.core.database import connect


SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_engine TEXT NOT NULL,
    source_run_id TEXT NOT NULL,
    source_record_id INTEGER NOT NULL,
    url TEXT,
    method TEXT,
    status_code INTEGER,
    context TEXT NOT NULL DEFAULT 'anonymous',
    request_hash TEXT,
    response_hash TEXT,
    request_size INTEGER,
    response_size INTEGER,
    request_truncated INTEGER NOT NULL DEFAULT 0,
    response_truncated INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(source_engine, source_run_id, source_record_id)
);

CREATE INDEX IF NOT EXISTS idx_traffic_evidence_source
ON traffic_evidence(source_engine, source_run_id, source_record_id);

CREATE INDEX IF NOT EXISTS idx_traffic_evidence_request_hash
ON traffic_evidence(request_hash);

CREATE INDEX IF NOT EXISTS idx_traffic_evidence_response_hash
ON traffic_evidence(response_hash);

CREATE INDEX IF NOT EXISTS idx_traffic_evidence_created
ON traffic_evidence(created_at);
"""


SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)"
    r"\s*:[^\r\n]*"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_traffic_evidence_schema(db_path: Path) -> None:
    connection = connect(db_path)
    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()


def _redact_common_headers(value: str) -> str:
    return SENSITIVE_HEADER_RE.sub(
        lambda match: f"{match.group(1)}: <redacted>",
        value,
    )


def _stringify_payload(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, str):
        return value

    if isinstance(value, dict):
        for key in (
            "raw",
            "raw_request",
            "raw_response",
            "request",
            "response",
            "data",
        ):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate

        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            default=str,
        )

    if isinstance(value, (list, tuple)):
        return json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            default=str,
        )

    return str(value)


def extract_request_response(data: dict) -> tuple[str | None, str | None]:
    request_value = None
    response_value = None

    for key in (
        "request",
        "raw_request",
        "request_raw",
    ):
        if key in data:
            request_value = data.get(key)
            break

    for key in (
        "response",
        "raw_response",
        "response_raw",
    ):
        if key in data:
            response_value = data.get(key)
            break

    request_text = _stringify_payload(request_value)
    response_text = _stringify_payload(response_value)

    if request_text:
        request_text = _redact_common_headers(request_text)

    if response_text:
        response_text = _redact_common_headers(response_text)

    return request_text, response_text


def _truncate_utf8(value: str, max_bytes: int) -> tuple[bytes, bool]:
    encoded = value.encode("utf-8", errors="replace")

    if len(encoded) <= max_bytes:
        return encoded, False

    marker = b"\n\n[reconmancer: evidence truncated]\n"
    keep = max(0, max_bytes - len(marker))
    return encoded[:keep] + marker, True


def _store_object(
    *,
    db_path: Path,
    project_root: Path,
    kind: str,
    content: bytes,
) -> tuple[str, int]:
    digest = hashlib.sha256(content).hexdigest()
    relative = Path("objects") / "evidence" / "traffic" / digest[:2] / f"{digest}.txt"
    absolute = project_root / relative
    absolute.parent.mkdir(parents=True, exist_ok=True)

    if not absolute.exists():
        temporary = absolute.with_suffix(".tmp")
        temporary.write_bytes(content)
        temporary.replace(absolute)

    size_bytes = absolute.stat().st_size

    connection = connect(db_path)
    try:
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
                digest,
                kind,
                str(relative),
                size_bytes,
                None,
                now_iso(),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return digest, size_bytes


def capture_traffic_evidence(
    *,
    db_path: Path,
    project_root: Path,
    source_engine: str,
    source_run_id: str,
    source_record_id: int | None,
    data: dict,
    url: str | None = None,
    context: str = "anonymous",
    max_bytes: int = 5 * 1024 * 1024,
) -> dict | None:
    if source_record_id is None:
        return None

    request_text, response_text = extract_request_response(data)

    if not request_text and not response_text:
        return None

    ensure_traffic_evidence_schema(db_path)

    request_hash = None
    response_hash = None
    request_size = None
    response_size = None
    request_truncated = False
    response_truncated = False

    if request_text:
        content, request_truncated = _truncate_utf8(
            request_text,
            max_bytes,
        )
        request_hash, request_size = _store_object(
            db_path=db_path,
            project_root=project_root,
            kind="http-request",
            content=content,
        )

    if response_text:
        content, response_truncated = _truncate_utf8(
            response_text,
            max_bytes,
        )
        response_hash, response_size = _store_object(
            db_path=db_path,
            project_root=project_root,
            kind="http-response",
            content=content,
        )

    method = None
    status_code = None

    request_data = data.get("request")
    response_data = data.get("response")

    if isinstance(request_data, dict):
        method = request_data.get("method")

    method = method or data.get("method")

    if isinstance(response_data, dict):
        status_code = response_data.get("status_code") or response_data.get("status")

    status_code = status_code or data.get("status_code")

    connection = connect(db_path)
    try:
        connection.execute(
            """
            INSERT INTO traffic_evidence (
                source_engine,
                source_run_id,
                source_record_id,
                url,
                method,
                status_code,
                context,
                request_hash,
                response_hash,
                request_size,
                response_size,
                request_truncated,
                response_truncated,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(
                source_engine,
                source_run_id,
                source_record_id
            )
            DO UPDATE SET
                url = excluded.url,
                method = excluded.method,
                status_code = excluded.status_code,
                context = excluded.context,
                request_hash = COALESCE(excluded.request_hash, traffic_evidence.request_hash),
                response_hash = COALESCE(excluded.response_hash, traffic_evidence.response_hash),
                request_size = COALESCE(excluded.request_size, traffic_evidence.request_size),
                response_size = COALESCE(excluded.response_size, traffic_evidence.response_size),
                request_truncated = excluded.request_truncated,
                response_truncated = excluded.response_truncated,
                created_at = excluded.created_at
            """,
            (
                source_engine,
                source_run_id,
                int(source_record_id),
                url,
                str(method) if method else None,
                int(status_code) if str(status_code).isdigit() else None,
                context or "anonymous",
                request_hash,
                response_hash,
                request_size,
                response_size,
                1 if request_truncated else 0,
                1 if response_truncated else 0,
                now_iso(),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return {
        "request_hash": request_hash,
        "response_hash": response_hash,
        "request_size": request_size,
        "response_size": response_size,
        "request_truncated": request_truncated,
        "response_truncated": response_truncated,
    }


def list_traffic_evidence(
    db_path: Path,
    *,
    engine: str = "",
    run_id: str = "",
    query: str = "",
    page: int = 1,
    per_page: int = 100,
) -> dict:
    ensure_traffic_evidence_schema(db_path)

    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 250))

    where = []
    params: list[Any] = []

    if engine:
        where.append("source_engine = ?")
        params.append(engine)

    if run_id:
        where.append("source_run_id = ?")
        params.append(run_id)

    if query:
        like = f"%{query}%"
        where.append(
            "(url LIKE ? OR source_run_id LIKE ? OR method LIKE ? OR context LIKE ?)"
        )
        params.extend([like, like, like, like])

    where_sql = ""
    if where:
        where_sql = "WHERE " + " AND ".join(where)

    connection = connect(db_path)
    try:
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM traffic_evidence {where_sql}",
                params,
            ).fetchone()[0]
        )

        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        offset = (page - 1) * per_page

        rows = connection.execute(
            f"""
            SELECT *
            FROM traffic_evidence
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, per_page, offset],
        ).fetchall()

        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "page": page,
            "pages": pages,
            "per_page": per_page,
        }
    finally:
        connection.close()


def get_traffic_evidence(
    db_path: Path,
    evidence_id: int,
) -> dict | None:
    ensure_traffic_evidence_schema(db_path)
    connection = connect(db_path)
    try:
        row = connection.execute(
            "SELECT * FROM traffic_evidence WHERE id = ?",
            (int(evidence_id),),
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def get_object_path(
    *,
    db_path: Path,
    project_root: Path,
    object_hash: str,
) -> Path | None:
    if not re.fullmatch(r"[0-9a-f]{64}", object_hash or ""):
        return None

    connection = connect(db_path)
    try:
        row = connection.execute(
            "SELECT relative_path FROM objects WHERE hash = ?",
            (object_hash,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    root = project_root.resolve()
    path = (project_root / row["relative_path"]).resolve()

    try:
        path.relative_to(root)
    except ValueError:
        return None

    return path if path.is_file() else None
