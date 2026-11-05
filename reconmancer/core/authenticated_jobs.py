from __future__ import annotations

from pathlib import Path

from reconmancer.core.scan_dispatch import dispatch_scan_job


def launch_httpx_authenticated_job(
    project: dict,
    payload: dict,
    targets: list[str] | None = None,
    *,
    target_file: Path | str | None = None,
) -> str:
    return dispatch_scan_job(
        project,
        engine="httpx",
        payload=payload,
        targets=targets,
        target_file=target_file,
        auth_profile_id=payload["auth_profile_id"],
    )


def launch_katana_authenticated_job(
    project: dict,
    payload: dict,
    targets: list[str] | None = None,
    *,
    target_file: Path | str | None = None,
) -> str:
    return dispatch_scan_job(
        project,
        engine="katana",
        payload=payload,
        targets=targets,
        target_file=target_file,
        auth_profile_id=payload["auth_profile_id"],
    )


def launch_nuclei_authenticated_job(
    project: dict,
    payload: dict,
    targets: list[str] | None = None,
    *,
    target_file: Path | str | None = None,
) -> str:
    return dispatch_scan_job(
        project,
        engine="nuclei",
        payload=payload,
        targets=targets,
        target_file=target_file,
        auth_profile_id=payload["auth_profile_id"],
    )
