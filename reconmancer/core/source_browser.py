from __future__ import annotations

import math
import re
from pathlib import Path
from urllib.parse import urlsplit

from reconmancer.core.database import (
    connect,
)

from reconmancer.core.findings_workspace import (
    VALID_ENGINES,
    ensure_findings_schema,
)


DEFAULT_PER_PAGE = 75
MAX_PER_PAGE = 200


VALID_CONTEXTS = {
    "all",
    "anonymous",
    "authenticated",
}


VALID_SEVERITIES = {
    "",
    "info",
    "low",
    "medium",
    "high",
    "critical",
    "unknown",
}


STATUS_GROUP_RE = re.compile(
    r"^[1-5]xx$",
    re.IGNORECASE,
)


STATUS_CODE_RE = re.compile(r"^[1-5][0-9][0-9]$")


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
        SELECT 1

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


def first_column(
    columns: set[str],
    candidates: tuple[str, ...],
) -> str | None:

    for candidate in candidates:
        if candidate in columns:
            return candidate

    return None


def sql_column(
    alias: str,
    columns: set[str],
    candidates: tuple[str, ...],
    *,
    default: str = "NULL",
) -> str:

    column = first_column(
        columns,
        candidates,
    )

    if column is None:
        return default

    return f"{alias}.{quote_identifier(column)}"


def url_host(
    value,
) -> str | None:

    if value is None:
        return None

    value = str(value).strip()

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


def register_sql_functions(
    connection,
) -> None:

    connection.create_function(
        "recon_url_host",
        1,
        url_host,
    )


def create_index_if_possible(
    connection,
    *,
    table: str,
    index_name: str,
    columns: tuple[str, ...],
) -> None:

    available = table_columns(
        connection,
        table,
    )

    if not set(columns).issubset(available):
        return

    column_sql = ", ".join(quote_identifier(column) for column in columns)

    connection.execute(
        f"""
        CREATE INDEX IF NOT EXISTS
            {quote_identifier(index_name)}

        ON
            {quote_identifier(table)}
            (
                {column_sql}
            )
        """
    )


def ensure_source_browser_indexes(
    connection,
) -> None:

    create_index_if_possible(
        connection,
        table="http_observations",
        index_name=("idx_http_obs_status_run"),
        columns=(
            "status_code",
            "run_id",
        ),
    )

    create_index_if_possible(
        connection,
        table="http_observations",
        index_name=("idx_http_obs_context"),
        columns=("context",),
    )

    create_index_if_possible(
        connection,
        table="katana_observations",
        index_name=("idx_katana_obs_status"),
        columns=("status_code",),
    )

    create_index_if_possible(
        connection,
        table="katana_observations",
        index_name=("idx_katana_obs_host"),
        columns=("host",),
    )

    create_index_if_possible(
        connection,
        table="nuclei_findings",
        index_name=("idx_nuclei_severity"),
        columns=("severity",),
    )

    create_index_if_possible(
        connection,
        table="nuclei_findings",
        index_name=("idx_nuclei_host"),
        columns=("host",),
    )

    create_index_if_possible(
        connection,
        table="nuclei_findings",
        index_name=("idx_nuclei_template"),
        columns=("template_id",),
    )

    connection.commit()


def build_httpx_base(
    connection,
) -> str | None:

    if not table_exists(
        connection,
        "http_observations",
    ):
        return None

    columns = table_columns(
        connection,
        "http_observations",
    )

    if not {
        "id",
        "run_id",
    }.issubset(columns):
        return None

    url_columns = table_columns(
        connection,
        "urls",
    )

    use_url_join = "url_id" in columns and "id" in url_columns

    if use_url_join:
        url_expression = sql_column(
            "u",
            url_columns,
            (
                "normalized_url",
                "url",
                "raw_url",
                "value",
            ),
        )

        host_column = first_column(
            url_columns,
            (
                "host",
                "hostname",
            ),
        )

        if host_column:
            host_expression = (
                "COALESCE("
                f"NULLIF(TRIM(u.{quote_identifier(host_column)}), ''), "
                f"recon_url_host({url_expression})"
                ")"
            )

        else:
            host_expression = f"recon_url_host({url_expression})"

        url_join = "LEFT JOIN urls u ON u.id = h.url_id"

    else:
        url_expression = sql_column(
            "h",
            columns,
            (
                "normalized_url",
                "url",
            ),
        )

        host_expression = f"recon_url_host({url_expression})"

        url_join = ""

    status_expression = sql_column(
        "h",
        columns,
        ("status_code",),
    )

    title_expression = sql_column(
        "h",
        columns,
        ("title",),
    )

    method_expression = sql_column(
        "h",
        columns,
        ("method",),
    )

    server_expression = sql_column(
        "h",
        columns,
        ("server",),
    )

    created_expression = sql_column(
        "h",
        columns,
        (
            "created_at",
            "timestamp",
        ),
        default="''",
    )

    if "context" in columns:
        context_expression = (
            "COALESCE("
            "NULLIF(TRIM(h.context), ''), "
            "NULLIF(TRIM(r.context), ''), "
            "'anonymous'"
            ")"
        )

    else:
        context_expression = "COALESCE(NULLIF(TRIM(r.context), ''), 'anonymous')"

    summary_expression = (
        "TRIM("
        f"COALESCE({method_expression}, '') "
        "|| ' ' || "
        f"COALESCE(CAST({status_expression} AS TEXT), '') "
        "|| ' ' || "
        f"COALESCE({title_expression}, '') "
        "|| ' ' || "
        f"COALESCE({server_expression}, '')"
        ")"
    )

    return f"""
        SELECT
            'httpx' AS engine,
            h.run_id AS run_id,
            h.id AS record_id,

            {host_expression}
                AS host,

            {url_expression}
                AS url,

            COALESCE(
                NULLIF(
                    TRIM(
                        CAST(
                            {title_expression}
                            AS TEXT
                        )
                    ),
                    ''
                ),
                'HTTP observation'
            )
                AS title,

            {summary_expression}
                AS summary,

            NULL
                AS severity,

            {context_expression}
                AS context,

            {status_expression}
                AS status_code,

            NULL
                AS template_id,

            {created_expression}
                AS created_at,

            CASE
                WHEN p.id IS NULL
                    THEN 0
                ELSE 1
            END
                AS pinned,

            p.id
                AS pin_id

        FROM
            http_observations h

        LEFT JOIN runs r
            ON r.id = h.run_id

        {url_join}

        LEFT JOIN investigation_pins p
            ON p.source_engine = 'httpx'
            AND p.source_run_id = h.run_id
            AND p.source_record_id = h.id
    """


def build_katana_base(
    connection,
) -> str | None:

    if not table_exists(
        connection,
        "katana_observations",
    ):
        return None

    columns = table_columns(
        connection,
        "katana_observations",
    )

    if not {
        "id",
        "run_id",
    }.issubset(columns):
        return None

    url_expression = sql_column(
        "k",
        columns,
        (
            "normalized_url",
            "url",
        ),
    )

    host_column = first_column(
        columns,
        (
            "host",
            "hostname",
        ),
    )

    if host_column:
        host_expression = (
            "COALESCE("
            f"NULLIF(TRIM(k.{quote_identifier(host_column)}), ''), "
            f"recon_url_host({url_expression})"
            ")"
        )

    else:
        host_expression = f"recon_url_host({url_expression})"

    status_expression = sql_column(
        "k",
        columns,
        ("status_code",),
    )

    method_expression = sql_column(
        "k",
        columns,
        ("method",),
    )

    source_kind_expression = sql_column(
        "k",
        columns,
        ("source_kind",),
    )

    tag_expression = sql_column(
        "k",
        columns,
        ("tag",),
    )

    created_expression = sql_column(
        "k",
        columns,
        (
            "created_at",
            "timestamp",
        ),
        default="''",
    )

    title_expression = (
        "COALESCE("
        f"NULLIF(TRIM({source_kind_expression}), ''), "
        f"NULLIF(TRIM({tag_expression}), ''), "
        "'Katana discovery'"
        ")"
    )

    summary_expression = (
        "TRIM("
        f"COALESCE({method_expression}, '') "
        "|| ' ' || "
        f"COALESCE(CAST({status_expression} AS TEXT), '') "
        "|| ' ' || "
        f"COALESCE({source_kind_expression}, '') "
        "|| ' ' || "
        f"COALESCE({tag_expression}, '')"
        ")"
    )

    return f"""
        SELECT
            'katana' AS engine,
            k.run_id AS run_id,
            k.id AS record_id,

            {host_expression}
                AS host,

            {url_expression}
                AS url,

            {title_expression}
                AS title,

            {summary_expression}
                AS summary,

            NULL
                AS severity,

            COALESCE(
                NULLIF(
                    TRIM(
                        r.context
                    ),
                    ''
                ),
                'anonymous'
            )
                AS context,

            {status_expression}
                AS status_code,

            NULL
                AS template_id,

            {created_expression}
                AS created_at,

            CASE
                WHEN p.id IS NULL
                    THEN 0
                ELSE 1
            END
                AS pinned,

            p.id
                AS pin_id

        FROM
            katana_observations k

        LEFT JOIN runs r
            ON r.id = k.run_id

        LEFT JOIN investigation_pins p
            ON p.source_engine = 'katana'
            AND p.source_run_id = k.run_id
            AND p.source_record_id = k.id
    """


def build_nuclei_base(
    connection,
) -> str | None:

    if not table_exists(
        connection,
        "nuclei_findings",
    ):
        return None

    columns = table_columns(
        connection,
        "nuclei_findings",
    )

    if not {
        "id",
        "run_id",
    }.issubset(columns):
        return None

    url_expression = sql_column(
        "n",
        columns,
        (
            "matched_at",
            "url",
        ),
    )

    host_column = first_column(
        columns,
        ("host",),
    )

    if host_column:
        host_expression = (
            "COALESCE("
            f"NULLIF(TRIM(n.{quote_identifier(host_column)}), ''), "
            f"recon_url_host({url_expression})"
            ")"
        )

    else:
        host_expression = f"recon_url_host({url_expression})"

    name_expression = sql_column(
        "n",
        columns,
        ("name",),
    )

    template_expression = sql_column(
        "n",
        columns,
        ("template_id",),
    )

    matcher_expression = sql_column(
        "n",
        columns,
        ("matcher_name",),
    )

    severity_expression = sql_column(
        "n",
        columns,
        ("severity",),
    )

    created_expression = sql_column(
        "n",
        columns,
        (
            "created_at",
            "timestamp",
        ),
        default="''",
    )

    title_expression = (
        "COALESCE("
        f"NULLIF(TRIM({name_expression}), ''), "
        f"NULLIF(TRIM({template_expression}), ''), "
        "'Nuclei finding'"
        ")"
    )

    summary_expression = (
        "TRIM("
        f"COALESCE({severity_expression}, '') "
        "|| ' ' || "
        f"COALESCE({template_expression}, '') "
        "|| ' ' || "
        f"COALESCE({matcher_expression}, '')"
        ")"
    )

    return f"""
        SELECT
            'nuclei' AS engine,
            n.run_id AS run_id,
            n.id AS record_id,

            {host_expression}
                AS host,

            {url_expression}
                AS url,

            {title_expression}
                AS title,

            {summary_expression}
                AS summary,

            LOWER(
                CAST(
                    {severity_expression}
                    AS TEXT
                )
            )
                AS severity,

            COALESCE(
                NULLIF(
                    TRIM(
                        r.context
                    ),
                    ''
                ),
                'anonymous'
            )
                AS context,

            NULL
                AS status_code,

            {template_expression}
                AS template_id,

            {created_expression}
                AS created_at,

            CASE
                WHEN p.id IS NULL
                    THEN 0
                ELSE 1
            END
                AS pinned,

            p.id
                AS pin_id

        FROM
            nuclei_findings n

        LEFT JOIN runs r
            ON r.id = n.run_id

        LEFT JOIN investigation_pins p
            ON p.source_engine = 'nuclei'
            AND p.source_run_id = n.run_id
            AND p.source_record_id = n.id
    """


def engine_base_queries(
    connection,
    engine: str,
) -> list[str]:

    builders = {
        "httpx": build_httpx_base,
        "katana": build_katana_base,
        "nuclei": build_nuclei_base,
    }

    if engine == "all":
        names = [
            "httpx",
            "katana",
            "nuclei",
        ]

    elif engine in VALID_ENGINES:
        names = [engine]

    else:
        names = [
            "httpx",
            "katana",
            "nuclei",
        ]

    output = []

    for name in names:
        query = builders[name](connection)

        if query:
            output.append(query)

    return output


def normalize_filters(
    *,
    engine: str,
    status: str,
    interesting: bool,
    severity: str,
    context: str,
    host: str,
    query: str,
    template_id: str,
    pinned_only: bool,
) -> dict:

    engine = engine.strip().lower()

    if engine != "all" and engine not in VALID_ENGINES:
        engine = "all"

    status = status.strip().lower()

    if not (STATUS_CODE_RE.fullmatch(status) or STATUS_GROUP_RE.fullmatch(status)):
        status = ""

    if interesting:
        status = ""

    severity = severity.strip().lower()

    if severity not in VALID_SEVERITIES:
        severity = ""

    context = context.strip().lower()

    if context not in VALID_CONTEXTS:
        context = "all"

    host = host.strip().lower().rstrip(".")

    return {
        "engine": engine,
        "status": status,
        "interesting": bool(interesting),
        "severity": severity,
        "context": context,
        "host": host,
        "query": (query.strip())[:500],
        "template_id": (template_id.strip())[:250],
        "pinned_only": bool(pinned_only),
    }


def filter_sql(
    filters: dict,
) -> tuple[
    str,
    list,
]:

    conditions = []

    parameters = []

    status = filters["status"]

    if status:
        if STATUS_CODE_RE.fullmatch(status):
            conditions.append("s.status_code = ?")

            parameters.append(int(status))

        else:
            hundred = int(status[0])

            minimum = hundred * 100

            conditions.append(("s.status_code BETWEEN ? AND ?"))

            parameters.extend(
                [
                    minimum,
                    minimum + 99,
                ]
            )

    if filters["interesting"]:
        conditions.append(
            """
            (
                s.status_code IN (
                    401,
                    403,
                    405,
                    429
                )

                OR

                s.status_code
                    BETWEEN 500 AND 599
            )
            """
        )

    if filters["severity"]:
        conditions.append(
            """
            LOWER(
                COALESCE(
                    s.severity,
                    ''
                )
            ) = ?
            """
        )

        parameters.append(filters["severity"])

    context = filters["context"]

    if context == "anonymous":
        conditions.append(
            """
            (
                s.context IS NULL

                OR

                s.context = ''

                OR

                s.context = 'anonymous'

                OR

                s.context NOT LIKE 'auth:%'
            )
            """
        )

    elif context == "authenticated":
        conditions.append(
            """
            s.context LIKE 'auth:%'
            """
        )

    if filters["host"]:
        conditions.append(
            """
            LOWER(
                COALESCE(
                    s.host,
                    ''
                )
            ) = ?
            """
        )

        parameters.append(filters["host"])

    if filters["template_id"]:
        conditions.append(
            """
            LOWER(
                COALESCE(
                    s.template_id,
                    ''
                )
            )
            LIKE LOWER(?)
            """
        )

        parameters.append("%" + filters["template_id"] + "%")

    if filters["query"]:
        like_value = "%" + filters["query"] + "%"

        conditions.append(
            """
            (
                s.run_id LIKE ?

                OR
                COALESCE(
                    s.host,
                    ''
                ) LIKE ?

                OR
                COALESCE(
                    s.url,
                    ''
                ) LIKE ?

                OR
                COALESCE(
                    s.title,
                    ''
                ) LIKE ?

                OR
                COALESCE(
                    s.summary,
                    ''
                ) LIKE ?

                OR
                COALESCE(
                    s.template_id,
                    ''
                ) LIKE ?

                OR
                COALESCE(
                    s.context,
                    ''
                ) LIKE ?
            )
            """
        )

        parameters.extend(
            [
                like_value,
                like_value,
                like_value,
                like_value,
                like_value,
                like_value,
                like_value,
            ]
        )

    if filters["pinned_only"]:
        conditions.append("s.pinned = 1")

    if not conditions:
        return (
            "",
            parameters,
        )

    return (
        " WHERE " + " AND ".join(conditions),
        parameters,
    )


def search_sources(
    db_path: Path,
    *,
    engine: str = "all",
    status: str = "",
    interesting: bool = False,
    severity: str = "",
    context: str = "all",
    host: str = "",
    query: str = "",
    template_id: str = "",
    pinned_only: bool = False,
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
) -> dict:

    ensure_findings_schema(db_path)

    filters = normalize_filters(
        engine=engine,
        status=status,
        interesting=interesting,
        severity=severity,
        context=context,
        host=host,
        query=query,
        template_id=template_id,
        pinned_only=pinned_only,
    )

    page = max(
        1,
        int(page),
    )

    per_page = max(
        1,
        min(
            int(per_page),
            MAX_PER_PAGE,
        ),
    )

    connection = connect(db_path)

    try:
        register_sql_functions(connection)

        ensure_source_browser_indexes(connection)

        bases = engine_base_queries(
            connection,
            filters["engine"],
        )

        if not bases:
            return {
                "items": [],
                "total": 0,
                "page": 1,
                "pages": 1,
                "per_page": per_page,
                "filters": filters,
            }

        union_sql = "\nUNION ALL\n".join(base for base in bases)

        where_sql, parameters = filter_sql(filters)

        filtered_sql = f"""
            SELECT *
            FROM (
                {union_sql}
            ) s
            {where_sql}
        """

        count_row = connection.execute(
            f"""
            SELECT
                COUNT(*) AS total

            FROM (
                {filtered_sql}
            )
            """,
            parameters,
        ).fetchone()

        total = int(count_row["total"] or 0)

        pages = max(
            1,
            math.ceil(total / per_page),
        )

        page = min(
            page,
            pages,
        )

        offset = (page - 1) * per_page

        rows = connection.execute(
            f"""
            SELECT *

            FROM (
                {filtered_sql}
            )

            ORDER BY
                created_at DESC,
                run_id DESC,
                record_id DESC

            LIMIT ?
            OFFSET ?
            """,
            [
                *parameters,
                per_page,
                offset,
            ],
        ).fetchall()

        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "page": page,
            "pages": pages,
            "per_page": per_page,
            "filters": filters,
        }

    finally:
        connection.close()


def correlation_conditions(
    context: str,
) -> str:

    conditions = [
        "s.host IS NOT NULL",
        "TRIM(s.host) != ''",
    ]

    if context == "authenticated":
        conditions.append("s.context LIKE 'auth:%'")

    elif context == "anonymous":
        conditions.append(
            """
            (
                s.context IS NULL

                OR
                s.context = ''

                OR
                s.context = 'anonymous'

                OR
                s.context NOT LIKE 'auth:%'
            )
            """
        )

    return "WHERE " + " AND ".join(conditions)


def correlation_matrix(
    db_path: Path,
    *,
    context: str = "all",
    limit: int = 100,
) -> list[dict]:

    ensure_findings_schema(db_path)

    context = context.strip().lower()

    if context not in VALID_CONTEXTS:
        context = "all"

    connection = connect(db_path)

    try:
        register_sql_functions(connection)

        bases = engine_base_queries(
            connection,
            "all",
        )

        if not bases:
            return []

        union_sql = "\nUNION ALL\n".join(bases)

        where_sql = correlation_conditions(context)

        rows = connection.execute(
            f"""
            SELECT
                s.host
                    AS host,

                SUM(
                    CASE
                        WHEN s.engine = 'httpx'
                            THEN 1
                        ELSE 0
                    END
                )
                    AS httpx,

                SUM(
                    CASE
                        WHEN s.engine = 'katana'
                            THEN 1
                        ELSE 0
                    END
                )
                    AS katana,

                SUM(
                    CASE
                        WHEN s.engine = 'nuclei'
                            THEN 1
                        ELSE 0
                    END
                )
                    AS nuclei,

                SUM(
                    CASE
                        WHEN s.status_code
                            BETWEEN 200 AND 299
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_2xx,

                SUM(
                    CASE
                        WHEN s.status_code
                            BETWEEN 300 AND 399
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_3xx,

                SUM(
                    CASE
                        WHEN s.status_code = 401
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_401,

                SUM(
                    CASE
                        WHEN s.status_code = 403
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_403,

                SUM(
                    CASE
                        WHEN s.status_code = 404
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_404,

                SUM(
                    CASE
                        WHEN s.status_code = 405
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_405,

                SUM(
                    CASE
                        WHEN s.status_code = 429
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_429,

                SUM(
                    CASE
                        WHEN s.status_code
                            BETWEEN 500 AND 599
                            THEN 1
                        ELSE 0
                    END
                )
                    AS status_5xx,

                SUM(
                    CASE
                        WHEN
                            s.engine = 'nuclei'
                            AND s.severity = 'high'
                            THEN 1
                        ELSE 0
                    END
                )
                    AS high,

                SUM(
                    CASE
                        WHEN
                            s.engine = 'nuclei'
                            AND s.severity = 'critical'
                            THEN 1
                        ELSE 0
                    END
                )
                    AS critical

            FROM (
                {union_sql}
            ) s

            {where_sql}

            GROUP BY
                s.host

            ORDER BY
                critical DESC,
                high DESC,
                status_5xx DESC,
                status_403 DESC,
                nuclei DESC,
                (
                    httpx
                    + katana
                    + nuclei
                ) DESC

            LIMIT ?
            """,
            (
                max(
                    1,
                    min(
                        limit,
                        500,
                    ),
                ),
            ),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def export_filtered_sources(
    db_path: Path,
    *,
    engine: str = "all",
    status: str = "",
    interesting: bool = False,
    severity: str = "",
    context: str = "all",
    host: str = "",
    query: str = "",
    template_id: str = "",
    pinned_only: bool = False,
    limit: int = 100000,
) -> list[dict]:
    """Return a bounded, server-side filtered handoff set without browser pagination."""
    ensure_findings_schema(db_path)
    filters = normalize_filters(
        engine=engine,
        status=status,
        interesting=interesting,
        severity=severity,
        context=context,
        host=host,
        query=query,
        template_id=template_id,
        pinned_only=pinned_only,
    )
    limit = max(1, min(int(limit), 100000))
    connection = connect(db_path)
    try:
        register_sql_functions(connection)
        ensure_source_browser_indexes(connection)
        bases = engine_base_queries(connection, filters["engine"])
        if not bases:
            return []
        union_sql = "\nUNION ALL\n".join(bases)
        where_sql, parameters = filter_sql(filters)
        rows = connection.execute(
            f"""
            SELECT *
            FROM (
                SELECT * FROM ({union_sql}) s
                {where_sql}
            )
            ORDER BY created_at DESC, run_id DESC, record_id DESC
            LIMIT ?
            """,
            [*parameters, limit],
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()
