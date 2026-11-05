from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import yaml

from reconmancer.core.auth_profiles import (
    filter_targets_for_profile,
    get_profile,
    profile_applies_to_target,
)


BASE_SENSITIVE_HEADERS = {
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


def auth_context(
    profile_id: str,
) -> str:

    return f"auth:{profile_id}"


def load_auth_profile(
    project_root: Path,
    profile_id: str,
) -> dict:

    try:
        profile = get_profile(
            project_root,
            profile_id,
        )

    except ValueError as exc:
        raise RuntimeError("Invalid authentication profile.") from exc

    if profile is None:
        raise RuntimeError((f"Authentication profile {profile_id} does not exist."))

    return profile


def credential_headers(
    profile: dict,
) -> dict[str, str]:

    credentials = profile.get(
        "credentials",
        {},
    )

    if not isinstance(
        credentials,
        dict,
    ):
        credentials = {}

    stored_headers = credentials.get(
        "headers",
        {},
    )

    if not isinstance(
        stored_headers,
        dict,
    ):
        stored_headers = {}

    output = {}

    for name, value in stored_headers.items():
        name = str(name).strip()

        value = str(value)

        if not name:
            continue

        output[name] = value

    cookie = credentials.get(
        "cookie",
        "",
    )

    if cookie:
        output["Cookie"] = str(cookie)

    return output


def profile_has_credentials(
    profile: dict,
) -> bool:

    return bool(credential_headers(profile))


def validate_targets(
    profile: dict,
    targets: list[str],
) -> None:

    (
        allowed,
        rejected,
    ) = filter_targets_for_profile(
        profile,
        targets,
    )

    if rejected:
        preview = ", ".join(rejected[:5])

        suffix = ""

        if len(rejected) > 5:
            suffix = f" (+{len(rejected) - 5} more)"

        raise RuntimeError(
            (
                "Authenticated scan rejected because "
                "some targets do not exactly match "
                "this authentication profile: "
                f"{preview}{suffix}"
            )
        )

    if len(allowed) != len(targets):
        raise RuntimeError(("Authentication target validation did not complete."))


def auth_temp_directory(
    project_root: Path,
    run_id: str,
) -> Path:

    root = project_root / "temp" / "auth"

    root.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    try:
        os.chmod(
            root,
            0o700,
        )

    except OSError:
        pass

    directory = root / run_id

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


def secure_write(
    path: Path,
    content: str,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    temporary = path.with_suffix(path.suffix + ".tmp")

    with temporary.open(
        "w",
        encoding="utf-8",
    ) as handle:
        handle.write(content)

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


def write_projectdiscovery_secret_file(
    project_root: Path,
    run_id: str,
    profile: dict,
) -> Path:

    headers = credential_headers(profile)

    if not headers:
        raise RuntimeError(
            ("Authentication profile contains no cookie or custom headers.")
        )

    scope = profile.get(
        "scope",
        {},
    )

    if not isinstance(
        scope,
        dict,
    ):
        raise RuntimeError("Authentication profile scope is invalid.")

    if scope.get("mode") != "exact-hosts":
        raise RuntimeError(("Only exact-host authentication profiles are supported."))

    hosts = scope.get(
        "hosts",
        [],
    )

    if (
        not isinstance(
            hosts,
            list,
        )
        or not hosts
    ):
        raise RuntimeError(("Authentication profile contains no allowed hosts."))

    document = {
        "id": (
            "reconmancer-"
            + str(
                profile.get(
                    "id",
                    "auth",
                )
            )
        ),
        "info": {
            "name": ("Reconmancer static authentication"),
            "author": ("reconmancer"),
        },
        "static": [
            {
                "type": "Header",
                "domains": [str(host) for host in hosts],
                "headers": [
                    {
                        "key": name,
                        "value": value,
                    }
                    for (
                        name,
                        value,
                    ) in headers.items()
                ],
            }
        ],
    }

    directory = auth_temp_directory(
        project_root,
        run_id,
    )

    path = directory / "secrets.yaml"

    content = yaml.safe_dump(
        document,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )

    secure_write(
        path,
        content,
    )

    return path


def write_katana_header_file(
    project_root: Path,
    run_id: str,
    profile: dict,
) -> Path:

    headers = credential_headers(profile)

    if not headers:
        raise RuntimeError(
            ("Authentication profile contains no cookie or custom headers.")
        )

    lines = []

    for (
        name,
        value,
    ) in headers.items():
        lines.append(f"{name}: {value}")

    directory = auth_temp_directory(
        project_root,
        run_id,
    )

    path = directory / "headers.txt"

    secure_write(
        path,
        "\n".join(lines) + "\n",
    )

    return path


def cleanup_auth_temp(
    project_root: Path,
    run_id: str,
) -> None:

    path = project_root / "temp" / "auth" / run_id

    try:
        shutil.rmtree(
            path,
            ignore_errors=True,
        )

    except OSError:
        pass


def secret_values(
    profile: dict,
) -> list[str]:

    values = []

    for value in credential_headers(profile).values():
        value = str(value)

        if not value:
            continue

        if value in values:
            continue

        values.append(value)

    values.sort(
        key=len,
        reverse=True,
    )

    return values


def sensitive_header_names(
    profile: dict,
) -> set[str]:

    names = set(BASE_SENSITIVE_HEADERS)

    for name in credential_headers(profile):
        names.add(name.lower())

    return names


def redact_text(
    value: str,
    profile: dict,
) -> str:

    output = str(value)

    for secret in secret_values(profile):
        output = output.replace(
            secret,
            "<redacted>",
        )

    for header_name in sensitive_header_names(profile):
        pattern = re.compile((r"(?im)^(" + re.escape(header_name) + r"\s*:)[^\r\n]*"))

        output = pattern.sub(
            r"\1 <redacted>",
            output,
        )

    return output


def redact_structure(
    value,
    profile: dict,
):

    sensitive = sensitive_header_names(profile)

    if isinstance(
        value,
        dict,
    ):
        output = {}

        for (
            key,
            item,
        ) in value.items():
            key_text = str(key)

            if key_text.lower() in sensitive:
                output[key] = "<redacted>"

            else:
                output[key] = redact_structure(
                    item,
                    profile,
                )

        return output

    if isinstance(
        value,
        list,
    ):
        return [
            redact_structure(
                item,
                profile,
            )
            for item in value
        ]

    if isinstance(
        value,
        tuple,
    ):
        return [
            redact_structure(
                item,
                profile,
            )
            for item in value
        ]

    if isinstance(
        value,
        str,
    ):
        return redact_text(
            value,
            profile,
        )

    return value


def redacted_json_line(
    data: dict,
    profile: dict,
) -> tuple[
    dict,
    str,
]:

    sanitized = redact_structure(
        data,
        profile,
    )

    line = json.dumps(
        sanitized,
        ensure_ascii=False,
        separators=(
            ",",
            ":",
        ),
    )

    return (
        sanitized,
        line,
    )


def target_is_authenticated(
    profile: dict,
    target: str,
) -> bool:

    return profile_applies_to_target(
        profile,
        target,
    )


def profile_hosts(
    profile: dict,
) -> list[str]:
    scope = profile.get("scope", {}) or {}
    hosts = scope.get("hosts", []) if isinstance(scope, dict) else []
    output = []
    seen = set()
    for host in hosts if isinstance(hosts, list) else []:
        value = str(host).strip().lower().rstrip(".")
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _chrome_regex_for_host(host: str) -> str:
    escaped = re.escape(host)
    return rf"^https?://{escaped}(?::[0-9]+)?(?:/|$)"


def write_chrome_auth_extension(
    project_root: Path,
    run_id: str,
    profile: dict,
    *,
    host: str | None = None,
) -> Path:
    """
    Build a temporary Manifest V3 extension that injects the profile's
    headers only when the destination URL hostname exactly matches an
    authorized host. This is used for authenticated browser/headless work.

    The extension lives under the project's protected temp/auth directory
    and is removed by cleanup_auth_temp().
    """
    headers = credential_headers(profile)
    if not headers:
        raise RuntimeError("Authentication profile contains no browser credentials.")

    allowed = profile_hosts(profile)
    if host is not None:
        normalized_host = str(host).strip().lower().rstrip(".")
        if normalized_host not in allowed:
            raise RuntimeError(
                f"Host {normalized_host} is not authorized by the authentication profile."
            )
        allowed = [normalized_host]

    if not allowed:
        raise RuntimeError("Authentication profile contains no allowed browser hosts.")

    directory = auth_temp_directory(project_root, run_id) / "chrome-extension"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass

    host_permissions = []
    rules = []
    rule_id = 1

    resource_types = [
        "main_frame",
        "sub_frame",
        "stylesheet",
        "script",
        "image",
        "font",
        "object",
        "xmlhttprequest",
        "ping",
        "csp_report",
        "media",
        "websocket",
        "webtransport",
        "webbundle",
        "other",
    ]

    for allowed_host in allowed:
        host_permissions.extend(
            [
                f"http://{allowed_host}/*",
                f"https://{allowed_host}/*",
            ]
        )

        rules.append(
            {
                "id": rule_id,
                "priority": 1,
                "action": {
                    "type": "modifyHeaders",
                    "requestHeaders": [
                        {
                            "header": name,
                            "operation": "set",
                            "value": value,
                        }
                        for name, value in headers.items()
                    ],
                },
                "condition": {
                    "regexFilter": _chrome_regex_for_host(allowed_host),
                    "resourceTypes": resource_types,
                },
            }
        )
        rule_id += 1

    manifest = {
        "manifest_version": 3,
        "name": "Reconmancer Host-Bound Authentication",
        "version": "1.0.0",
        "permissions": [
            "declarativeNetRequest",
            "declarativeNetRequestWithHostAccess",
        ],
        "host_permissions": host_permissions,
        "declarative_net_request": {
            "rule_resources": [
                {
                    "id": "reconmancer_auth_rules",
                    "enabled": True,
                    "path": "rules.json",
                }
            ]
        },
    }

    secure_write(
        directory / "manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2),
    )
    secure_write(
        directory / "rules.json",
        json.dumps(rules, ensure_ascii=False, indent=2),
    )

    return directory
