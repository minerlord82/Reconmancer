from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import (
    parse_qsl,
    urlparse,
)

from reconmancer.core.database import connect

from reconmancer.core.repository import (
    normalize_url,
    now_iso,
    upsert_url,
)

from reconmancer.engines.katana.schema import (
    ensure_katana_schema,
)


def stringify(
    value,
) -> str | None:

    if value is None:
        return None

    if isinstance(
        value,
        (
            dict,
            list,
        ),
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


def get_request(
    data: dict,
) -> dict:

    request_data = data.get("request")

    if isinstance(
        request_data,
        dict,
    ):
        return request_data

    return {}


def get_response(
    data: dict,
) -> dict:

    response = data.get("response")

    if isinstance(
        response,
        dict,
    ):
        return response

    return {}


def extract_endpoint(
    data: dict,
) -> str | None:

    request_data = get_request(data)

    value = (
        request_data.get("endpoint")
        or request_data.get("url")
        or data.get("endpoint")
        or data.get("url")
    )

    if not isinstance(
        value,
        str,
    ):
        return None

    value = value.strip()

    if not value:
        return None

    return value


def extract_source(
    data: dict,
) -> str | None:

    request_data = get_request(data)

    source = request_data.get("source") or data.get("source")

    if isinstance(
        source,
        str,
    ):
        return source

    if isinstance(
        source,
        dict,
    ):
        value = source.get("url") or source.get("endpoint")

        if isinstance(
            value,
            str,
        ):
            return value

    return None


def extract_method(
    data: dict,
) -> str | None:

    request_data = get_request(data)

    value = request_data.get("method") or data.get("method")

    if not value:
        return None

    return str(value).upper()


def extract_tag(
    data: dict,
) -> str | None:

    request_data = get_request(data)

    value = request_data.get("tag") or data.get("tag")

    if value is None:
        return None

    return str(value)


def extract_attribute(
    data: dict,
) -> str | None:

    request_data = get_request(data)

    value = request_data.get("attribute") or data.get("attribute")

    if value is None:
        return None

    return str(value)


def extract_status_code(
    data: dict,
) -> int | None:

    response = get_response(data)

    value = response.get("status_code") or data.get("status_code")

    if value is None:
        return None

    try:
        return int(value)

    except (
        TypeError,
        ValueError,
    ):
        return None


def extract_content_type(
    data: dict,
) -> str | None:

    response = get_response(data)

    value = response.get("content_type")

    if value:
        return str(value)

    headers = response.get("headers")

    if isinstance(
        headers,
        dict,
    ):
        for key in (
            "content_type",
            "content-type",
            "Content-Type",
        ):
            value = headers.get(key)

            if value:
                return str(value)

    return None


def extract_technologies(
    data: dict,
):

    response = get_response(data)

    return response.get("technologies") or data.get("technologies") or []


def safe_normalize(
    value: str,
) -> str:

    try:
        if value.startswith(
            (
                "http://",
                "https://",
            )
        ):
            return normalize_url(value)

    except Exception:
        pass

    return value


def extract_url_shape(
    value: str,
) -> tuple[
    str,
    str,
    list[str],
    str,
]:

    try:
        parsed = urlparse(value)

        host = (parsed.hostname or "").lower()

        path = parsed.path or "/"

        query_keys = []

        seen = set()

        for key, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        ):
            if key in seen:
                continue

            seen.add(key)

            query_keys.append(key)

        query_keys.sort()

        signature = "&".join(query_keys)

        return (
            host,
            path,
            query_keys,
            signature,
        )

    except Exception:
        return (
            "",
            "",
            [],
            "",
        )


def detect_javascript(
    *,
    url: str,
    content_type: str | None,
    tag: str | None,
) -> bool:

    try:
        path = (urlparse(url).path or "").lower()

    except Exception:
        path = ""

    if path.endswith(
        (
            ".js",
            ".mjs",
        )
    ):
        return True

    if content_type:
        lowered = content_type.lower()

        if "javascript" in lowered or "ecmascript" in lowered:
            return True

    if tag and tag.lower() == "script":
        return True

    return False


def get_header(
    headers: dict,
    name: str,
) -> str | None:

    wanted = name.lower()

    for key, value in headers.items():
        if str(key).lower() != wanted:
            continue

        if value is None:
            return None

        return str(value)

    return None


def detect_runtime_request(
    *,
    data: dict,
    profile: str,
) -> bool:

    if profile not in {
        "headless",
        "deep",
    }:
        return False

    request_data = get_request(data)

    #
    # Headless Katana emits actual browser
    # requests. Presence of browser-style
    # headers is a useful signal that this
    # record came from the browser execution
    # stage rather than static extraction.
    #
    headers = request_data.get("headers")

    if not isinstance(
        headers,
        dict,
    ):
        return False

    user_agent = get_header(
        headers,
        "User-Agent",
    )

    referer = get_header(
        headers,
        "Referer",
    )

    origin = get_header(
        headers,
        "Origin",
    )

    accept_language = get_header(
        headers,
        "Accept-Language",
    )

    return bool(user_agent and (referer or origin or accept_language))


def detect_xhr_candidate(
    *,
    data: dict,
    profile: str,
    runtime: bool,
) -> bool:

    if not runtime:
        return False

    if profile not in {
        "headless",
        "deep",
    }:
        return False

    request_data = get_request(data)

    headers = request_data.get("headers")

    if not isinstance(
        headers,
        dict,
    ):
        headers = {}

    method = str(request_data.get("method") or "GET").upper()

    accept = (
        get_header(
            headers,
            "Accept",
        )
        or ""
    ).lower()

    origin = get_header(
        headers,
        "Origin",
    )

    content_type = (
        get_header(
            headers,
            "Content-Type",
        )
        or ""
    ).lower()

    sec_fetch_mode = (
        get_header(
            headers,
            "Sec-Fetch-Mode",
        )
        or ""
    ).lower()

    sec_fetch_dest = (
        get_header(
            headers,
            "Sec-Fetch-Dest",
        )
        or ""
    ).lower()

    requested_with = (
        get_header(
            headers,
            "X-Requested-With",
        )
        or ""
    ).lower()

    if requested_with == ("xmlhttprequest"):
        return True

    if sec_fetch_mode in {
        "cors",
        "same-origin",
    } and sec_fetch_dest in {
        "",
        "empty",
    }:
        return True

    # Non-navigation methods are strong runtime signals.
    
    if method not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }:
        return True

    # fetch/XHR commonly uses */* instead of a navigation Accept header.
    
    if accept == "*/*" and origin:
        return True

    if any(
        marker in content_type
        for marker in (
            "application/json",
            "application/graphql",
            "application/x-www-form-urlencoded",
        )
    ):
        return True

    return False


def determine_source_kind(
    *,
    tag: str | None,
    attribute: str | None,
    javascript: bool,
    runtime: bool,
    xhr: bool,
) -> str:

    if xhr:
        return "xhr"

    if runtime:
        return "runtime"

    attribute_lower = attribute.lower() if attribute else ""

    tag_lower = tag.lower() if tag else ""

    if attribute_lower.startswith("jsluice"):
        return "js-static"

    if tag_lower == "form":
        return "form"

    if javascript:
        return "javascript"

    return "page"


def process_result(
    db_path: Path,
    run_id: str,
    data: dict,
    *,
    profile: str = "standard",
) -> dict:

    ensure_katana_schema(db_path)

    endpoint = extract_endpoint(data)

    if not endpoint:
        return {
            "stored": False,
            "url": None,
            "xhr": False,
            "runtime": False,
        }

    normalized = safe_normalize(endpoint)

    if normalized.startswith(
        (
            "http://",
            "https://",
        )
    ):
        try:
            upsert_url(
                db_path,
                normalized,
            )

        except Exception:
            pass

    source_url = extract_source(data)

    method = extract_method(data)

    status_code = extract_status_code(data)

    content_type = extract_content_type(data)

    technologies = extract_technologies(data)

    tag = extract_tag(data)

    attribute = extract_attribute(data)

    (
        host,
        path,
        query_keys,
        query_signature,
    ) = extract_url_shape(normalized)

    javascript = detect_javascript(
        url=normalized,
        content_type=content_type,
        tag=tag,
    )

    runtime = detect_runtime_request(
        data=data,
        profile=profile,
    )

    xhr = detect_xhr_candidate(
        data=data,
        profile=profile,
        runtime=runtime,
    )

    source_kind = determine_source_kind(
        tag=tag,
        attribute=attribute,
        javascript=javascript,
        runtime=runtime,
        xhr=xhr,
    )

    raw_json = json.dumps(
        data,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )

    connection = connect(db_path)

    try:
        cursor = connection.execute(
            """
            INSERT INTO katana_observations (

                run_id,
                profile,

                url,
                normalized_url,

                host,
                path,
                query_signature,

                source_url,

                method,
                status_code,

                content_type,

                tag,
                attribute,

                technologies_json,
                query_keys_json,

                is_javascript,
                is_query,
                is_xhr,
                is_runtime,

                source_kind,

                raw_json,

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

                ?
            )
            """,
            (
                run_id,
                profile,
                endpoint,
                normalized,
                host,
                path,
                query_signature,
                source_url,
                method,
                status_code,
                content_type,
                tag,
                attribute,
                stringify(technologies),
                stringify(query_keys),
                1 if javascript else 0,
                1 if query_keys else 0,
                1 if xhr else 0,
                1 if runtime else 0,
                source_kind,
                raw_json,
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
        "url": normalized,
        "xhr": xhr,
        "runtime": runtime,
        "record_id": record_id,
    }
