from __future__ import annotations

import hashlib
import json
from pathlib import Path

from reconmancer.core.database import connect

from reconmancer.core.repository import (
    now_iso,
)

from reconmancer.engines.nuclei.schema import (
    ensure_nuclei_schema,
)


def compact_json(
    value,
) -> str | None:

    if value is None:
        return None

    return json.dumps(
        value,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )


def as_list(
    value,
) -> list:

    if value is None:
        return []

    if isinstance(
        value,
        list,
    ):
        return value

    if isinstance(
        value,
        tuple,
    ):
        return list(value)

    if isinstance(
        value,
        str,
    ):
        if "," in value:
            return [item.strip() for item in value.split(",") if item.strip()]

        if value.strip():
            return [value.strip()]

    return [value]


def first_value(
    *values,
):

    for value in values:
        if value is None:
            continue

        if isinstance(
            value,
            str,
        ):
            if value.strip():
                return value.strip()

            continue

        return value

    return None


def create_fingerprint(
    data: dict,
) -> str:

    info = data.get("info")

    if not isinstance(
        info,
        dict,
    ):
        info = {}

    value = {
        "template_id": (data.get("template-id") or data.get("template_id")),
        "matcher_name": (data.get("matcher-name") or data.get("matcher_name")),
        "host": (data.get("host")),
        "matched_at": (data.get("matched-at") or data.get("matched_at")),
        "url": (data.get("url")),
        "name": (info.get("name")),
        "extracted": (
            data.get("extracted-results") or data.get("extracted_results") or []
        ),
    }

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def process_result(
    db_path: Path,
    run_id: str,
    data: dict,
) -> dict:

    ensure_nuclei_schema(db_path)

    info = data.get("info")

    if not isinstance(
        info,
        dict,
    ):
        info = {}

    classification = info.get("classification")

    if not isinstance(
        classification,
        dict,
    ):
        classification = {}

    template_id = first_value(
        data.get("template-id"),
        data.get("template_id"),
    )

    template_path = first_value(
        data.get("template-path"),
        data.get("template_path"),
    )

    matcher_name = first_value(
        data.get("matcher-name"),
        data.get("matcher_name"),
    )

    severity = first_value(
        info.get("severity"),
        data.get("severity"),
        "unknown",
    )

    severity = str(severity).lower()

    cve = first_value(
        classification.get("cve-id"),
        classification.get("cve_id"),
    )

    cwe = first_value(
        classification.get("cwe-id"),
        classification.get("cwe_id"),
    )

    cvss_score = first_value(
        classification.get("cvss-score"),
        classification.get("cvss_score"),
    )

    try:
        if cvss_score is not None:
            cvss_score = float(cvss_score)

    except (
        TypeError,
        ValueError,
    ):
        cvss_score = None

    fingerprint = create_fingerprint(data)

    connection = connect(db_path)

    try:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO nuclei_findings (

                run_id,

                fingerprint,

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
                authors_json,

                description,

                references_json,

                cve_json,
                cwe_json,

                cvss_score,
                cvss_metrics,

                extracted_results_json,

                timestamp,

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
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
                ?,
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
                fingerprint,
                template_id,
                template_path,
                matcher_name,
                info.get("name"),
                severity,
                first_value(
                    data.get("type"),
                    data.get("protocol"),
                ),
                data.get("host"),
                data.get("url"),
                first_value(
                    data.get("matched-at"),
                    data.get("matched_at"),
                ),
                data.get("ip"),
                str(data.get("port")) if data.get("port") is not None else None,
                compact_json(as_list(info.get("tags"))),
                compact_json(as_list(info.get("author"))),
                info.get("description"),
                compact_json(as_list(info.get("reference"))),
                compact_json(as_list(cve)),
                compact_json(as_list(cwe)),
                cvss_score,
                first_value(
                    classification.get("cvss-metrics"),
                    classification.get("cvss_metrics"),
                ),
                compact_json(
                    as_list(
                        first_value(
                            data.get("extracted-results"),
                            data.get("extracted_results"),
                        )
                    )
                ),
                data.get("timestamp"),
                now_iso(),
            ),
        )

        connection.commit()

        stored = cursor.rowcount > 0

        row = connection.execute(
            """
            SELECT id
            FROM nuclei_findings
            WHERE run_id = ? AND fingerprint = ?
            """,
            (
                run_id,
                fingerprint,
            ),
        ).fetchone()

        record_id = int(row["id"]) if row is not None else None

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return {
        "stored": stored,
        "fingerprint": fingerprint,
        "severity": severity,
        "record_id": record_id,
    }
