from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from reconmancer.core.auth_profiles import target_hostname
from reconmancer.core.auth_runtime import (
    auth_context,
    cleanup_auth_temp,
    load_auth_profile,
    redacted_json_line,
    validate_targets,
    write_chrome_auth_extension,
    write_katana_header_file,
)
from reconmancer.core.projects import load_project
from reconmancer.core.scan_watchdog import (
    ScanInterruptedError,
    iter_process_stdout,
)
from reconmancer.core.repository import create_run, finish_run, next_run_id
from reconmancer.core.tooling import get_tool_path
from reconmancer.core.traffic_evidence import capture_traffic_evidence
from reconmancer.engines.katana.parser import process_result
from reconmancer.engines.katana.schema import ensure_katana_schema


HOME = Path("/opt/reconmancer")
VALID_PROFILES = {"standard", "headless", "deep"}
VALID_PAGE_LOAD_STRATEGIES = {
    "heuristic",
    "load",
    "domcontentloaded",
    "networkidle",
    "none",
}
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024


def read_targets(path: Path) -> list[str]:
    targets: list[str] = []
    seen = set()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#") or value in seen:
                continue
            seen.add(value)
            targets.append(value)
    return targets


def find_system_chrome() -> str | None:
    for candidate in (
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ):
        value = shutil.which(candidate)
        if value:
            return value
    return None


def group_targets_by_host(targets: list[str]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for target in targets:
        host = target_hostname(target)
        if not host:
            raise RuntimeError(
                f"Katana authenticated target has no valid hostname: {target}"
            )
        output.setdefault(host, []).append(target)
    return output


def build_command(
    *,
    katana_path: Path,
    input_file: Path,
    profile: str,
    depth: int,
    rate_limit: int,
    concurrency: int,
    parallelism: int,
    js_crawl: bool,
    known_files: bool,
    form_extraction: bool,
    tech_detect: bool,
    no_scope: bool,
    page_load_strategy: str,
    auth_headers_file: Path | None = None,
    exact_fqdn_scope: bool = False,
    browser_extension: Path | None = None,
    chrome_data_dir: Path | None = None,
) -> list[str]:
    if profile not in VALID_PROFILES:
        raise ValueError(f"Invalid Katana profile: {profile}")

    if page_load_strategy not in VALID_PAGE_LOAD_STRATEGIES:
        page_load_strategy = "heuristic"

    command = [
        str(katana_path),
        "-list",
        str(input_file),
        "-silent",
        "-jsonl",
        "-nc",
        "-d",
        str(depth),
        "-c",
        str(concurrency),
        "-p",
        str(parallelism),
        "-rl",
        str(rate_limit),
        "-timeout",
        "10",
        "-retry",
        "1",
        "-do",
    ]

    if js_crawl:
        command.append("-jc")
    if known_files and depth >= 3:
        command.extend(["-kf", "all"])
    if form_extraction:
        command.append("-fx")
    if tech_detect:
        command.append("-td")

    if exact_fqdn_scope:
        command.extend(["-fs", "fqdn"])
    elif no_scope:
        command.append("-ns")

    if auth_headers_file is not None:
        command.extend(["-H", str(auth_headers_file)])

    if profile in {"headless", "deep"}:
        command.extend(["-hl", "-xhr", "-pls", page_load_strategy])

        chrome_path = find_system_chrome()
        if chrome_path:
            command.extend(["-scp", chrome_path])

        if browser_extension is not None:
            # The generated extension uses exact-host regex rules, so browser
            # credentials cannot be attached to third-party subresources.
            command.extend(
                [
                    "-ho",
                    f"--load-extension={browser_extension}",
                    "-ho",
                    f"--disable-extensions-except={browser_extension}",
                ]
            )

        if chrome_data_dir is not None:
            chrome_data_dir.mkdir(parents=True, exist_ok=True)
            command.extend(["-noi", "-cdd", str(chrome_data_dir)])

        if hasattr(os, "geteuid") and os.geteuid() == 0:
            command.append("-nos")

    if profile == "deep":
        command.append("-jsl")

    return command


def write_host_target_file(
    raw_directory: Path,
    host: str,
    targets: list[str],
) -> Path:
    suffix = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
    path = raw_directory / f"auth-host-{suffix}-targets.txt"
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return path


def run_katana(
    project_slug: str,
    *,
    target_file: Path,
    profile: str = "standard",
    depth: int = 3,
    rate_limit: int = 20,
    concurrency: int = 5,
    parallelism: int = 2,
    js_crawl: bool = True,
    known_files: bool = True,
    form_extraction: bool = True,
    tech_detect: bool = True,
    no_scope: bool = False,
    page_load_strategy: str = "heuristic",
    auth_profile_id: str | None = None,
    on_run_started=None,
) -> str:
    if profile not in VALID_PROFILES:
        raise ValueError(f"Unsupported Katana profile: {profile}")

    project = load_project(HOME, project_slug)
    root = project["root"]
    db_path = project["database"]
    ensure_katana_schema(db_path)

    targets = read_targets(target_file)
    if not targets:
        raise RuntimeError("Katana target file is empty.")

    auth_profile = None
    run_context = "anonymous"

    if auth_profile_id:
        if no_scope:
            raise RuntimeError("Authenticated Katana cannot disable crawl scope.")
        auth_profile = load_auth_profile(root, auth_profile_id)
        validate_targets(auth_profile, targets)
        run_context = auth_context(auth_profile_id)

    katana_path = get_tool_path("katana")
    run_id = next_run_id(db_path, "katana")
    raw_directory = root / "raw" / "katana" / run_id
    raw_directory.mkdir(parents=True, exist_ok=True)
    raw_jsonl = raw_directory / "results.jsonl"
    stderr_path = raw_directory / "stderr.log"
    command_path = raw_directory / "command.txt"

    create_run(
        db_path,
        run_id,
        engine="katana",
        profile=profile,
        context=run_context,
    )

    if on_run_started is not None:
        on_run_started(run_id)

    result_count = 0

    try:
        target_groups = (
            group_targets_by_host(targets)
            if auth_profile is not None
            else {"anonymous": targets}
        )

        command_lines: list[str] = []

        with (
            raw_jsonl.open("a", encoding="utf-8") as raw_output,
            stderr_path.open("a", encoding="utf-8") as stderr_output,
        ):
            for group_name, group_targets in target_groups.items():
                if auth_profile is not None:
                    group_file = write_host_target_file(
                        raw_directory,
                        group_name,
                        group_targets,
                    )
                else:
                    group_file = target_file

                auth_headers_file = None
                browser_extension = None
                chrome_data_dir = None

                if auth_profile is not None:
                    if profile in {"headless", "deep"}:
                        browser_extension = write_chrome_auth_extension(
                            root,
                            f"{run_id}-{hashlib.sha256(group_name.encode()).hexdigest()[:8]}",
                            auth_profile,
                            host=group_name,
                        )
                        chrome_data_dir = (
                            root
                            / "temp"
                            / "auth"
                            / run_id
                            / "chrome-data"
                            / hashlib.sha256(group_name.encode()).hexdigest()[:12]
                        )
                    else:
                        auth_headers_file = write_katana_header_file(
                            root,
                            run_id,
                            auth_profile,
                        )

                command = build_command(
                    katana_path=katana_path,
                    input_file=group_file,
                    profile=profile,
                    depth=depth,
                    rate_limit=rate_limit,
                    concurrency=concurrency,
                    parallelism=parallelism,
                    js_crawl=js_crawl,
                    known_files=known_files,
                    form_extraction=form_extraction,
                    tech_detect=tech_detect,
                    no_scope=no_scope,
                    page_load_strategy=page_load_strategy,
                    auth_headers_file=auth_headers_file,
                    exact_fqdn_scope=auth_profile is not None,
                    browser_extension=browser_extension,
                    chrome_data_dir=chrome_data_dir,
                )

                command_line = " ".join(command)
                command_lines.append(command_line)

                stderr_output.write("=" * 80 + "\n")
                stderr_output.write(f"PROFILE: {profile}\n")
                stderr_output.write(f"CONTEXT: {run_context}\n")
                if auth_profile is not None:
                    stderr_output.write(f"AUTH EXACT HOST: {group_name}\n")
                    if profile in {"headless", "deep"}:
                        stderr_output.write("AUTH BROWSER: exact-host extension\n")
                if profile in {"headless", "deep"}:
                    stderr_output.write(f"CHROME: {find_system_chrome()}\n")
                stderr_output.write("COMMAND:\n" + command_line + "\n")
                stderr_output.write("=" * 80 + "\n")
                stderr_output.flush()

                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=stderr_output,
                    text=True,
                    bufsize=1,
                )
                assert process.stdout is not None

                idle_timeout = 600 if profile in {"headless", "deep"} else 300

                for line in iter_process_stdout(
                    process,
                    idle_timeout_seconds=idle_timeout,
                    engine_name=f"Katana {profile}",
                ):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        stderr_output.write("INVALID JSON:\n")
                        if auth_profile is None:
                            stderr_output.write(line + "\n")
                        else:
                            stderr_output.write(
                                "<redacted invalid authenticated JSON>\n"
                            )
                        stderr_output.flush()
                        continue

                    if auth_profile is not None:
                        data, stored_line = redacted_json_line(data, auth_profile)
                    else:
                        stored_line = line

                    raw_output.write(stored_line + "\n")
                    raw_output.flush()

                    result = process_result(
                        db_path,
                        run_id,
                        data,
                        profile=profile,
                    )

                    if result.get("stored"):
                        result_count += 1
                        try:
                            capture_traffic_evidence(
                                db_path=db_path,
                                project_root=root,
                                source_engine="katana",
                                source_run_id=run_id,
                                source_record_id=result.get("record_id"),
                                data=data,
                                url=result.get("url"),
                                context=run_context,
                                max_bytes=MAX_EVIDENCE_BYTES,
                            )
                        except Exception as exc:
                            stderr_output.write(f"EVIDENCE CAPTURE ERROR: {exc}\n")
                            stderr_output.flush()

                return_code = process.wait()
                if return_code != 0:
                    raise RuntimeError(
                        f"Katana exited with status {return_code}. See stderr.log."
                    )

        command_path.write_text("\n\n".join(command_lines) + "\n", encoding="utf-8")

        finish_run(
            db_path,
            run_id,
            status="completed",
            input_count=len(targets),
            result_count=result_count,
        )
        return run_id

    except ScanInterruptedError as exc:
        finish_run(
            db_path,
            run_id,
            status="interrupted",
            input_count=len(targets),
            result_count=result_count,
            error=str(exc),
        )
        raise

    except Exception as exc:
        finish_run(
            db_path,
            run_id,
            status="failed",
            input_count=len(targets),
            result_count=result_count,
            error=str(exc),
        )
        raise

    finally:
        if auth_profile is not None:
            # Headless extensions may have been created in sibling run-id dirs.
            cleanup_auth_temp(root, run_id)
            auth_root = root / "temp" / "auth"
            if auth_root.exists():
                for child in auth_root.glob(f"{run_id}-*"):
                    shutil.rmtree(child, ignore_errors=True)
