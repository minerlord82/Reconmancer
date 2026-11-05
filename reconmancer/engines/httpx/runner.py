from __future__ import annotations

import json
import subprocess
from pathlib import Path

from reconmancer.core.auth_runtime import (
    auth_context,
    cleanup_auth_temp,
    load_auth_profile,
    redacted_json_line,
    target_is_authenticated,
    validate_targets,
    write_projectdiscovery_secret_file,
)
from reconmancer.core.projects import load_project
from reconmancer.core.scan_watchdog import (
    ScanInterruptedError,
    iter_process_stdout,
)
from reconmancer.core.repository import (
    create_run,
    finish_run,
    next_run_id,
    normalize_url,
)
from reconmancer.core.tooling import get_tool_path
from reconmancer.core.traffic_evidence import capture_traffic_evidence
from reconmancer.engines.httpx.parser import process_result


HOME = Path("/opt/reconmancer")
DEFAULT_MAX_REDIRECT_DEPTH = 10
MAX_EVIDENCE_RESPONSE_BYTES = 5 * 1024 * 1024


def read_targets(path: Path) -> list[str]:
    values: list[str] = []
    seen = set()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if not value or value.startswith("#") or value in seen:
                continue
            seen.add(value)
            values.append(value)
    return values


def build_command(
    httpx_path: Path,
    input_file: Path,
    rate_limit: int,
    *,
    secret_file: Path | None = None,
) -> list[str]:
    command = [
        str(httpx_path),
        "-l",
        str(input_file),
        "-silent",
        "-json",
        "-sc",
        "-cl",
        "-ct",
        "-location",
        "-favicon",
        "-hash",
        "sha256",
        "-jarm",
        "-rt",
        "-lc",
        "-wc",
        "-title",
        "-server",
        "-td",
        "-ip",
        "-cname",
        "-asn",
        "-cdn",
        "-method",
        "-websocket",
        "-http2",
        "-tls-grab",
        "-extract-fqdn",
        # Preserve matched request/response material in JSONL so Reconmancer
        # can externalize it into content-addressed evidence objects.
        "-irr",
        "-rstr",
        str(MAX_EVIDENCE_RESPONSE_BYTES),
        "-rl",
        str(rate_limit),
        "-t",
        "20",
        "-timeout",
        "10",
    ]

    if secret_file is not None:
        command.extend(["-sf", str(secret_file)])

    return command


def result_target(data: dict) -> str | None:
    for key in ("url", "final_url", "input"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def run_httpx(
    project_slug: str,
    *,
    target_file: Path | None = None,
    rate_limit: int = 10,
    max_redirect_depth: int = DEFAULT_MAX_REDIRECT_DEPTH,
    auth_profile_id: str | None = None,
    on_run_started=None,
) -> str:
    project = load_project(HOME, project_slug)
    root = project["root"]
    db_path = project["database"]

    if target_file is None:
        target_file = root / "input" / "targets.txt"

    targets = read_targets(target_file)
    if not targets:
        raise RuntimeError("Target file is empty.")

    auth_profile = None
    run_context = "anonymous"

    if auth_profile_id:
        auth_profile = load_auth_profile(root, auth_profile_id)
        validate_targets(auth_profile, targets)
        run_context = auth_context(auth_profile_id)

    httpx_path = get_tool_path("httpx")
    run_id = next_run_id(db_path, "httpx")
    raw_directory = root / "raw" / "httpx" / run_id
    raw_directory.mkdir(parents=True, exist_ok=True)
    stderr_path = raw_directory / "stderr.log"
    raw_jsonl_path = raw_directory / "results.jsonl"

    create_run(
        db_path,
        run_id,
        engine="httpx",
        profile="full",
        context=run_context,
    )

    if on_run_started is not None:
        on_run_started(run_id)

    input_count = 0
    result_count = 0
    seen_targets: set[str] = set()
    current_targets = targets
    depth = 0
    secret_file = None

    try:
        if auth_profile is not None:
            secret_file = write_projectdiscovery_secret_file(
                root,
                run_id,
                auth_profile,
            )

        with (
            raw_jsonl_path.open("a", encoding="utf-8") as raw_output,
            stderr_path.open("a", encoding="utf-8") as stderr_output,
        ):
            while current_targets and depth <= max_redirect_depth:
                batch: list[str] = []

                for target in current_targets:
                    cleaned = target.strip()
                    if not cleaned or cleaned in seen_targets:
                        continue
                    seen_targets.add(cleaned)
                    batch.append(cleaned)

                if not batch:
                    break

                input_count += len(batch)
                batch_file = raw_directory / f"depth-{depth:02d}-targets.txt"
                batch_file.write_text("\n".join(batch) + "\n", encoding="utf-8")

                command = build_command(
                    httpx_path,
                    batch_file,
                    rate_limit,
                    secret_file=secret_file,
                )

                # The command only contains a path to the protected secret file,
                # never the secret values themselves.
                stderr_output.write(
                    "\n\n"
                    + "=" * 80
                    + f"\nDEPTH {depth}\nCONTEXT: {run_context}\nCOMMAND:\n"
                    + " ".join(command)
                    + "\n"
                    + "=" * 80
                    + "\n"
                )
                stderr_output.flush()

                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=stderr_output,
                    text=True,
                    bufsize=1,
                )

                next_targets: list[str] = []
                assert process.stdout is not None

                for line in iter_process_stdout(
                    process,
                    idle_timeout_seconds=300,
                    engine_name="HTTPX",
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

                    observation_context = "anonymous"
                    target = result_target(data)

                    if (
                        auth_profile is not None
                        and target
                        and target_is_authenticated(auth_profile, target)
                    ):
                        observation_context = run_context

                    result = process_result(
                        db_path,
                        run_id,
                        data,
                        depth=depth,
                        context=observation_context,
                    )

                    if result.get("stored"):
                        result_count += 1
                        try:
                            capture_traffic_evidence(
                                db_path=db_path,
                                project_root=root,
                                source_engine="httpx",
                                source_run_id=run_id,
                                source_record_id=result.get("record_id"),
                                data=data,
                                url=result.get("url"),
                                context=observation_context,
                                max_bytes=MAX_EVIDENCE_RESPONSE_BYTES,
                            )
                        except Exception as exc:
                            stderr_output.write(f"EVIDENCE CAPTURE ERROR: {exc}\n")
                            stderr_output.flush()

                    redirect = result.get("redirect")
                    if redirect:
                        try:
                            normalized = normalize_url(redirect)
                        except Exception:
                            continue

                        if normalized not in seen_targets:
                            next_targets.append(normalized)

                return_code = process.wait()
                if return_code != 0:
                    raise RuntimeError(
                        f"HTTPX exited with status {return_code}. See stderr.log."
                    )

                current_targets = next_targets
                depth += 1

        finish_run(
            db_path,
            run_id,
            status="completed",
            input_count=input_count,
            result_count=result_count,
        )
        return run_id

    except ScanInterruptedError as exc:
        finish_run(
            db_path,
            run_id,
            status="interrupted",
            input_count=input_count,
            result_count=result_count,
            error=str(exc),
        )
        raise

    except Exception as exc:
        finish_run(
            db_path,
            run_id,
            status="failed",
            input_count=input_count,
            result_count=result_count,
            error=str(exc),
        )
        raise

    finally:
        if auth_profile is not None:
            cleanup_auth_temp(root, run_id)
