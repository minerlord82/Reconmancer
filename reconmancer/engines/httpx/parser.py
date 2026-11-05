from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urljoin

from reconmancer.core.database import connect
from reconmancer.core.repository import (
    normalize_url,
    now_iso,
    upsert_url,
)


_DURATION = re.compile(
    r"^\s*"
    r"([0-9.]+)"
    r"\s*"
    r"(ms|s|us|µs|ns)?"
    r"\s*$",
    re.IGNORECASE,
)


def duration_to_ms(
    value,
) -> float | None:
    """
    Convert HTTPX duration values into milliseconds.

    Examples:
        95.2ms -> 95.2
        1.5s   -> 1500
        250us  -> 0.25
        500ns  -> 0.0005
    """

    if value is None:
        return None

    if isinstance(
        value,
        (int, float),
    ):
        return float(value)

    match = _DURATION.match(str(value))

    if not match:
        return None

    number = float(match.group(1))

    unit = (match.group(2) or "ms").lower()

    if unit == "s":
        return number * 1000.0

    if unit in (
        "us",
        "µs",
    ):
        return number / 1000.0

    if unit == "ns":
        return number / 1_000_000.0

    return number


def stringify(
    value,
) -> str | None:
    """
    Convert values into compact strings suitable
    for SQLite storage.

    Lists and dictionaries are kept as JSON.
    """

    if value is None:
        return None

    if isinstance(
        value,
        (dict, list),
    ):
        return json.dumps(
            value,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
        )

    return str(value)


def get_url_from_result(
    data: dict,
) -> str | None:
    """
    Extract the primary URL from an HTTPX JSON object.
    """

    candidates = [
        data.get("url"),
        data.get("final_url"),
    ]

    for value in candidates:
        if not isinstance(
            value,
            str,
        ):
            continue

        if value.startswith(
            (
                "http://",
                "https://",
            )
        ):
            return value

    return None


def extract_redirect(
    source_url: str,
    data: dict,
) -> str | None:
    """
    Resolve an HTTP redirect destination.

    Handles both absolute Location headers:

        https://example.org/path

    and relative redirects:

        /login
    """

    location = data.get("location") or data.get("redirect_location")

    if not location:
        return None

    try:
        destination = urljoin(
            source_url,
            str(location),
        )

        return normalize_url(destination)

    except Exception:
        return None


def extract_hashes(
    data: dict,
) -> tuple[
    str | None,
    str | None,
]:
    """
    Extract body and header SHA256 hashes.

    HTTPX v1.12 generally returns:

        "hash": {
            "body_sha256": "...",
            "header_sha256": "..."
        }
    """

    hashes = data.get("hash")

    if not hashes:
        return (
            None,
            None,
        )

    if isinstance(
        hashes,
        dict,
    ):
        body_hash = hashes.get("body_sha256") or hashes.get("sha256")

        header_hash = hashes.get("header_sha256")

        return (
            stringify(body_hash),
            stringify(header_hash),
        )

    return (
        stringify(hashes),
        None,
    )


def process_result(
    db_path: Path,
    run_id: str,
    data: dict,
    *,
    depth: int = 0,
    context: str = "anonymous",
) -> dict:
    """
    Normalize and store one HTTPX JSON result.

    Stores:

        - URL
        - asset
        - HTTP metadata
        - technology fingerprints
        - IP / CNAME / ASN
        - CDN / WAF information
        - body/header hashes
        - JARM
        - TLS object
        - HTTP/2 state
        - WebSocket state
        - redirect relationship

    Redirect destinations are also inserted into the
    URL/asset database so the runner can later send
    them back through HTTPX.
    """

    source_url = get_url_from_result(data)

    if not source_url:
        return {
            "stored": False,
            "redirect": None,
            "url": None,
        }

    try:
        source_url = normalize_url(source_url)

    except Exception:
        return {
            "stored": False,
            "redirect": None,
            "url": None,
        }

    url_id = upsert_url(
        db_path,
        source_url,
    )

    technologies = data.get("tech") or data.get("technologies") or []

    (
        body_hash,
        header_hash,
    ) = extract_hashes(data)

    redirect = extract_redirect(
        source_url,
        data,
    )

    response_time = duration_to_ms(data.get("time") or data.get("response_time"))

    
    # HTTPX has used both JARM field names across versions.
    
    jarm = data.get("jarm_hash") or data.get("jarm")

    
    # Important:
    #
    # If there is a redirect, create/update its URL
    # BEFORE opening the observation transaction.
    #
    # upsert_url() opens its own SQLite connection.
    # Doing this while another write transaction is
    # active could cause "database is locked".
    
    destination_url_id = None

    if redirect:
        destination_url_id = upsert_url(
            db_path,
            redirect,
        )

    connection = connect(db_path)

    try:
        cursor = connection.execute(
            """
            INSERT INTO http_observations (
                run_id,
                url_id,
                context,

                status_code,

                title,

                content_type,
                content_length,

                line_count,
                word_count,

                response_time_ms,

                method,

                server,
                technologies_json,

                ip,
                cname,
                asn,

                cdn,
                cdn_name,
                cdn_type,

                redirect_location,

                body_hash,
                header_hash,

                favicon_hash,
                jarm,

                tls_json,

                http2,
                websocket,

                screenshot_hash,

                created_at
            )

            VALUES (
                ?, ?, ?,
                ?,
                ?,
                ?, ?,
                ?, ?,
                ?,
                ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?,
                ?,
                ?
            )
            """,
            (
                run_id,
                url_id,
                context,
                data.get("status_code"),
                data.get("title"),
                data.get("content_type"),
                data.get("content_length"),
                data.get("lines") or data.get("line_count"),
                data.get("words") or data.get("word_count"),
                response_time,
                data.get("method"),
                data.get("webserver") or data.get("server"),
                stringify(technologies),
                data.get("host_ip") or data.get("ip"),
                stringify(data.get("cname")),
                stringify(data.get("asn")),
                stringify(data.get("cdn")),
                data.get("cdn_name"),
                data.get("cdn_type"),
                redirect,
                body_hash,
                header_hash,
                stringify(data.get("favicon")),
                stringify(jarm),
                stringify(data.get("tls")),
                1 if data.get("http2") else 0,
                1 if data.get("websocket") else 0,
                None,
                now_iso(),
            ),
        )

        if redirect:
            connection.execute(
                """
                INSERT INTO redirects (
                    run_id,

                    source_url_id,

                    status_code,

                    destination_url,
                    destination_url_id,

                    depth,

                    context,

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
                    ?
                )
                """,
                (
                    run_id,
                    url_id,
                    data.get("status_code"),
                    redirect,
                    destination_url_id,
                    depth,
                    context,
                    now_iso(),
                ),
            )

        record_id = int(cursor.lastrowid)

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "stored": True,
        "redirect": redirect,
        "url": source_url,
        "record_id": record_id,
    }
