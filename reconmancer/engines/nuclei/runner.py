from __future__ import annotations

import json
import subprocess
from pathlib import Path

from reconmancer.core.auth_runtime import (
    auth_context,
    cleanup_auth_temp,
    load_auth_profile,
    redacted_json_line,
    validate_targets,
    write_chrome_auth_extension,
    write_projectdiscovery_secret_file,
)
from reconmancer.core.projects import load_project
from reconmancer.core.nuclei_templates import (
    default_nuclei_status,
    projectdiscovery_repo_path,
    projectdiscovery_template_status,
)
from reconmancer.core.repository import create_run, finish_run, next_run_id
from reconmancer.core.tooling import get_tool_path
from reconmancer.core.traffic_evidence import capture_traffic_evidence
from reconmancer.engines.nuclei.parser import process_result
from reconmancer.engines.nuclei.schema import ensure_nuclei_schema


HOME = Path("/opt/reconmancer")
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
VALID_TEMPLATE_SOURCES = {"default", "projectdiscovery"}
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


def sanitize_csv(value: str) -> str:
    values: list[str] = []
    seen = set()
    for item in value.split(","):
        item = item.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        values.append(item)
    return ",".join(values)


def build_command(
    *,
    nuclei_path: Path,
    target_file: Path,
    severities: list[str],
    tags: str,
    exclude_tags: str,
    rate_limit: int,
    concurrency: int,
    bulk_size: int,
    no_interactsh: bool,
    allow_headless: bool,
    template_source: str = "default",
    secret_file: Path | None = None,
    browser_extension: Path | None = None,
) -> list[str]:
    valid_severities = []
    for severity in severities:
        lowered = severity.strip().lower()
        if lowered in VALID_SEVERITIES and lowered not in valid_severities:
            valid_severities.append(lowered)

    if not valid_severities:
        valid_severities = ["info", "low", "medium", "high", "critical"]

    protocol_types = "http,ssl,headless" if allow_headless else "http,ssl"

    if template_source not in VALID_TEMPLATE_SOURCES:
        template_source = "default"

    command = [
        str(nuclei_path),
        "-l",
        str(target_file),
        "-silent",
        "-nc",
        # Reconmancer owns template updates. Never update/check during a scan.
        "-duc",
        # Let Nuclei handle individual hung templates internally.
        "-hm",
        "-j",
        "-ts",
        "-ot",
        "-severity",
        ",".join(valid_severities),
        "-type",
        protocol_types,
        "-rl",
        str(rate_limit),
        "-c",
        str(concurrency),
        "-bs",
        str(bulk_size),
        "-timeout",
        "10",
        "-retries",
        "1",
        # Keep request/response pairs in JSON findings so Reconmancer can
        # externalize them into content-addressed evidence objects.
        "-irr",
        "-rss",
        str(MAX_EVIDENCE_BYTES),
    ]

    if template_source == "projectdiscovery":
        repository = projectdiscovery_repo_path()
        if not repository.is_dir():
            raise RuntimeError(
                "nuclei-templates (ProjectDiscovery) is not installed. "
                "Open Settings and click Update Nuclei Templates first."
            )
        command.extend(["-t", str(repository)])

    cleaned_tags = sanitize_csv(tags)
    if cleaned_tags:
        command.extend(["-tags", cleaned_tags])

    cleaned_exclusions = sanitize_csv(exclude_tags)
    if cleaned_exclusions:
        command.extend(["-etags", cleaned_exclusions])

    if no_interactsh:
        command.append("-ni")

    if allow_headless:
        command.extend(["-headless", "-sc"])
        if browser_extension is not None:
            command.extend(
                [
                    "-ho",
                    f"--load-extension={browser_extension}",
                    "-ho",
                    f"--disable-extensions-except={browser_extension}",
                ]
            )
    else:
        command.extend(["-exclude-type", "headless"])

    if secret_file is not None:
        command.extend(["-sf", str(secret_file)])

    return command


def run_nuclei(
    project_slug: str,
    *,
    target_file: Path,
    severities: list[str],
    tags: str = "",
    exclude_tags: str = "dos,fuzz,bruteforce",
    rate_limit: int = 10,
    concurrency: int = 5,
    bulk_size: int = 5,
    no_interactsh: bool = True,
    allow_headless: bool = False,
    template_source: str = "default",
    auth_profile_id: str | None = None,
    on_run_started=None,
) -> str:
    if template_source not in VALID_TEMPLATE_SOURCES:
        template_source = "default"

    project = load_project(HOME, project_slug)
    root = project["root"]
    db_path = project["database"]
    ensure_nuclei_schema(db_path)

    targets = read_targets(target_file)
    if not targets:
        raise RuntimeError("Nuclei target file is empty.")

    auth_profile = None
    run_context = "anonymous"

    if auth_profile_id:
        auth_profile = load_auth_profile(root, auth_profile_id)
        validate_targets(auth_profile, targets)
        run_context = auth_context(auth_profile_id)
        # Authenticated baseline keeps OAST disabled unless we later add an
        # explicit authenticated-OAST policy.
        no_interactsh = True

    nuclei_path = get_tool_path("nuclei")
    run_id = next_run_id(db_path, "nuclei")
    raw_directory = root / "raw" / "nuclei" / run_id
    raw_directory.mkdir(parents=True, exist_ok=True)
    raw_jsonl_path = raw_directory / "results.jsonl"
    stderr_path = raw_directory / "stderr.log"
    command_path = raw_directory / "command.txt"

    create_run(
        db_path,
        run_id,
        engine="nuclei",
        profile=(
            "web-safe-projectdiscovery"
            if template_source == "projectdiscovery"
            else "web-safe-default-nuclei"
        ),
        context=run_context,
    )

    if on_run_started is not None:
        on_run_started(run_id)

    result_count = 0
    secret_file = None
    browser_extension = None

    try:
        if auth_profile is not None:
            secret_file = write_projectdiscovery_secret_file(
                root,
                run_id,
                auth_profile,
            )
            if allow_headless:
                browser_extension = write_chrome_auth_extension(
                    root,
                    run_id,
                    auth_profile,
                )

        command = build_command(
            nuclei_path=nuclei_path,
            target_file=target_file,
            severities=severities,
            tags=tags,
            exclude_tags=exclude_tags,
            rate_limit=rate_limit,
            concurrency=concurrency,
            bulk_size=bulk_size,
            no_interactsh=no_interactsh,
            allow_headless=allow_headless,
            template_source=template_source,
            secret_file=secret_file,
            browser_extension=browser_extension,
        )

        command_path.write_text(" ".join(command) + "\n", encoding="utf-8")

        with (
            raw_jsonl_path.open("a", encoding="utf-8") as raw_output,
            stderr_path.open("a", encoding="utf-8") as stderr_output,
        ):
            stderr_output.write("=" * 80 + "\n")
            if template_source == "projectdiscovery":
                template_status = projectdiscovery_template_status()
                template_label = "nuclei-templates (ProjectDiscovery)"
            else:
                template_status = default_nuclei_status()
                template_label = "Default Nuclei"

            stderr_output.write("PROFILE: web-safe\n")
            stderr_output.write(f"TEMPLATE SOURCE: {template_label}\n")
            stderr_output.write(
                f"TEMPLATES: {template_status.get('version', 'Unknown')}\n"
            )
            stderr_output.write(f"CONTEXT: {run_context}\n")
            if auth_profile is not None and allow_headless:
                stderr_output.write("AUTH BROWSER: exact-host extension\n")
            stderr_output.write("COMMAND:\n" + " ".join(command) + "\n")
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

            for line in process.stdout:
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
                        stderr_output.write("<redacted invalid authenticated JSON>\n")
                    stderr_output.flush()
                    continue

                if auth_profile is not None:
                    data, stored_line = redacted_json_line(data, auth_profile)
                else:
                    stored_line = line

                raw_output.write(stored_line + "\n")
                raw_output.flush()

                result = process_result(db_path, run_id, data)

                if result.get("stored"):
                    result_count += 1

                if result.get("record_id") is not None:
                    try:
                        evidence_url = (
                            data.get("matched-at")
                            or data.get("matched_at")
                            or data.get("url")
                            or data.get("host")
                        )
                        capture_traffic_evidence(
                            db_path=db_path,
                            project_root=root,
                            source_engine="nuclei",
                            source_run_id=run_id,
                            source_record_id=result.get("record_id"),
                            data=data,
                            url=str(evidence_url) if evidence_url else None,
                            context=run_context,
                            max_bytes=MAX_EVIDENCE_BYTES,
                        )
                    except Exception as exc:
                        stderr_output.write(f"EVIDENCE CAPTURE ERROR: {exc}\n")
                        stderr_output.flush()

            return_code = process.wait()
            if return_code != 0:
                raise RuntimeError(
                    f"Nuclei exited with status {return_code}. See stderr.log."
                )

        finish_run(
            db_path,
            run_id,
            status="completed",
            input_count=len(targets),
            result_count=result_count,
        )
        return run_id

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
            cleanup_auth_temp(root, run_id)
