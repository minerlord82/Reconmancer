from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml


MAX_DOMAINS = 100
MAX_HEADERS = 50
MAX_HEADER_BYTES = 32768
MAX_COOKIE_BYTES = 16384
MAX_NOTES_BYTES = 4096


HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


BLOCKED_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "upgrade",
}


def now_iso() -> str:

    return datetime.now(timezone.utc).isoformat()


def auth_directory(
    project_root: Path,
) -> Path:

    directory = project_root / "secrets" / "auth"

    directory.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    try:
        os.chmod(
            directory,
            0o700,
        )

    except OSError:
        pass

    return directory


def normalize_domain(
    value: str,
) -> str:

    value = value.strip().lower()

    if not value:
        raise ValueError("Empty host.")

    if "*" in value:
        raise ValueError(("Wildcard authentication domains are not allowed."))

    if "://" in value:
        parsed = urlsplit(value)

    else:
        parsed = urlsplit("//" + value)

    host = (parsed.hostname or "").strip().lower()

    host = host.rstrip(".")

    if not host:
        raise ValueError(f"Invalid host: {value}")

    if len(host) > 253:
        raise ValueError("Host is too long.")

    return host


def parse_domains(
    raw: str,
) -> list[str]:

    output = []
    seen = set()

    for line in raw.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        host = normalize_domain(line)

        if host in seen:
            continue

        seen.add(host)

        output.append(host)

        if len(output) > MAX_DOMAINS:
            raise ValueError(
                (f"Authentication profile may contain at most {MAX_DOMAINS} hosts.")
            )

    if not output:
        raise ValueError(("At least one exact host is required."))

    return output


def parse_headers(
    raw: str,
) -> dict[str, str]:

    output = {}

    total_bytes = 0

    for line in raw.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if ":" not in line:
            raise ValueError(("Every custom header must use: Header-Name: value"))

        name, value = line.split(
            ":",
            1,
        )

        name = name.strip()
        value = value.strip()

        if not name:
            raise ValueError("Header name is empty.")

        if not HEADER_NAME_RE.fullmatch(name):
            raise ValueError((f"Invalid HTTP header name: {name}"))

        lowered = name.lower()

        if lowered in BLOCKED_HEADERS:
            raise ValueError(
                (
                    f"{name} is controlled "
                    "by the HTTP client and "
                    "cannot be stored in an "
                    "authentication profile."
                )
            )

        if lowered == "cookie":
            raise ValueError(
                (
                    "Use the dedicated Cookie "
                    "field instead of adding a "
                    "Cookie header manually."
                )
            )

        if "\r" in value or "\n" in value:
            raise ValueError(("Header values cannot contain newlines."))

        canonical_name = name

        # Preserve the first-seen casing for duplicate header names.
        
        for existing in list(output):
            if existing.lower() == lowered:
                canonical_name = existing

                break

        output[canonical_name] = value

        total_bytes += len(name.encode("utf-8"))

        total_bytes += len(value.encode("utf-8"))

        if len(output) > MAX_HEADERS:
            raise ValueError(
                (f"Authentication profile may contain at most {MAX_HEADERS} headers.")
            )

        if total_bytes > MAX_HEADER_BYTES:
            raise ValueError(("Custom headers are too large."))

    return output


def validate_cookie(
    value: str,
) -> str:

    value = value.strip()

    if "\r" in value or "\n" in value:
        raise ValueError(("Cookie value cannot contain newlines."))

    if len(value.encode("utf-8")) > MAX_COOKIE_BYTES:
        raise ValueError("Cookie value is too large.")

    return value


def validate_notes(
    value: str,
) -> str:

    value = value.strip()

    if len(value.encode("utf-8")) > MAX_NOTES_BYTES:
        raise ValueError("Profile notes are too large.")

    return value


def profile_path(
    project_root: Path,
    profile_id: str,
) -> Path:

    if not re.fullmatch(
        r"AP-[0-9a-f]{12}",
        profile_id,
    ):
        raise ValueError(("Invalid authentication profile ID."))

    return auth_directory(project_root) / (profile_id + ".yaml")


def write_profile(
    path: Path,
    profile: dict,
) -> None:

    temporary = path.with_suffix(".yaml.tmp")

    with temporary.open(
        "w",
        encoding="utf-8",
    ) as handle:
        yaml.safe_dump(
            profile,
            handle,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )

        handle.flush()

        os.fsync(handle.fileno())

    try:
        os.chmod(
            temporary,
            0o600,
        )

    except OSError:
        pass

    os.replace(
        temporary,
        path,
    )

    try:
        os.chmod(
            path,
            0o600,
        )

    except OSError:
        pass


def create_profile(
    project_root: Path,
    *,
    name: str,
    domains_raw: str,
    headers_raw: str,
    cookie: str,
    notes: str,
) -> dict:

    name = name.strip()

    if not name:
        raise ValueError("Profile name is required.")

    if len(name) > 100:
        raise ValueError("Profile name is too long.")

    domains = parse_domains(domains_raw)

    headers = parse_headers(headers_raw)

    cookie = validate_cookie(cookie)

    notes = validate_notes(notes)

    profile_id = "AP-" + uuid.uuid4().hex[:12]

    timestamp = now_iso()

    profile = {
        "id": profile_id,
        "name": name,
        "created_at": timestamp,
        "updated_at": timestamp,
        "scope": {
            "mode": "exact-hosts",
            "hosts": domains,
        },
        "credentials": {
            "headers": headers,
            "cookie": cookie,
        },
        "notes": notes,
    }

    path = profile_path(
        project_root,
        profile_id,
    )

    write_profile(
        path,
        profile,
    )

    return profile


def read_profile_file(
    path: Path,
) -> dict | None:

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))

    except (
        OSError,
        yaml.YAMLError,
    ):
        return None

    if not isinstance(
        data,
        dict,
    ):
        return None

    return data


def get_profile(
    project_root: Path,
    profile_id: str,
) -> dict | None:

    path = profile_path(
        project_root,
        profile_id,
    )

    if not path.is_file():
        return None

    return read_profile_file(path)


def public_profile(
    profile: dict,
) -> dict:

    scope = profile.get("scope", {})

    credentials = profile.get("credentials", {})

    if not isinstance(
        scope,
        dict,
    ):
        scope = {}

    if not isinstance(
        credentials,
        dict,
    ):
        credentials = {}

    headers = credentials.get("headers", {})

    if not isinstance(
        headers,
        dict,
    ):
        headers = {}

    cookie = credentials.get("cookie", "")

    hosts = scope.get("hosts", [])

    if not isinstance(
        hosts,
        list,
    ):
        hosts = []

    return {
        "id": profile.get("id"),
        "name": profile.get("name"),
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
        "hosts": hosts,
        "host_count": len(hosts),
        "header_names": sorted(
            headers.keys(),
            key=str.lower,
        ),
        "header_count": len(headers),
        "has_cookie": bool(cookie),
        "notes": profile.get(
            "notes",
            "",
        ),
    }


def list_profiles(
    project_root: Path,
) -> list[dict]:

    directory = auth_directory(project_root)

    output = []

    for path in directory.glob("AP-*.yaml"):
        profile = read_profile_file(path)

        if profile is None:
            continue

        output.append(public_profile(profile))

    output.sort(
        key=lambda item: item.get("created_at") or "",
        reverse=True,
    )

    return output


def delete_profile(
    project_root: Path,
    profile_id: str,
) -> None:

    path = profile_path(
        project_root,
        profile_id,
    )

    if not path.is_file():
        raise ValueError(("Authentication profile does not exist."))

    path.unlink()


def target_hostname(
    target: str,
) -> str | None:

    target = target.strip()

    if not target:
        return None

    try:
        if "://" in target:
            parsed = urlsplit(target)

        else:
            parsed = urlsplit("//" + target)

        host = parsed.hostname

    except ValueError:
        return None

    if not host:
        return None

    return host.strip().lower().rstrip(".")


def profile_applies_to_target(
    profile: dict,
    target: str,
) -> bool:

    host = target_hostname(target)

    if not host:
        return False

    scope = profile.get("scope", {})

    if not isinstance(
        scope,
        dict,
    ):
        return False

    if scope.get("mode") != "exact-hosts":
        return False

    allowed = scope.get("hosts", [])

    if not isinstance(
        allowed,
        list,
    ):
        return False

    normalized_allowed = {str(item).strip().lower().rstrip(".") for item in allowed}

    return host in normalized_allowed


def build_auth_headers(
    profile: dict,
    target: str,
) -> dict[str, str]:

    if not profile_applies_to_target(
        profile,
        target,
    ):
        return {}

    credentials = profile.get("credentials", {})

    if not isinstance(
        credentials,
        dict,
    ):
        return {}

    stored_headers = credentials.get("headers", {})

    if not isinstance(
        stored_headers,
        dict,
    ):
        stored_headers = {}

    output = {}

    for name, value in stored_headers.items():
        output[str(name)] = str(value)

    cookie = credentials.get("cookie", "")

    if cookie:
        output["Cookie"] = str(cookie)

    return output


def filter_targets_for_profile(
    profile: dict,
    targets: list[str],
) -> tuple[
    list[str],
    list[str],
]:

    allowed = []
    rejected = []

    for target in targets:
        if profile_applies_to_target(
            profile,
            target,
        ):
            allowed.append(target)

        else:
            rejected.append(target)

    return (
        allowed,
        rejected,
    )
