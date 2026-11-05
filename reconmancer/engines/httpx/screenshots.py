from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from reconmancer.core.auth_profiles import (
    profile_applies_to_target,
    target_hostname,
)

from reconmancer.core.auth_runtime import (
    auth_context,
    cleanup_auth_temp,
    load_auth_profile,
    write_chrome_auth_extension,
    write_projectdiscovery_secret_file,
)

from reconmancer.core.database import connect
from reconmancer.core.projects import load_project
from reconmancer.core.repository import now_iso
from reconmancer.core.tooling import get_tool_path


HOME = Path("/opt/reconmancer")


SCREENSHOT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
}

MIN_SCREENSHOT_BYTES = 128


def sha256_file(
    path: Path,
) -> str:

    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def system_chrome_available() -> bool:

    candidates = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ]

    for candidate in candidates:
        if shutil.which(candidate):
            return True

    return False


def valid_generated_image(
    path: Path,
) -> bool:
    """
    Verify that a generated screenshot is a real,
    non-empty PNG/JPEG/WebP image.

    We intentionally do this before hashing or
    registering the screenshot in SQLite.
    """

    if not path.is_file():
        return False

    if path.suffix.lower() not in IMAGE_EXTENSIONS:
        return False

    try:
        size = path.stat().st_size

    except OSError:
        return False

    if size < MIN_SCREENSHOT_BYTES:
        return False

    try:
        with path.open("rb") as handle:
            header = handle.read(16)

    except OSError:
        return False

    #
    # PNG
    #
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return True

    #
    # JPEG
    #
    if header.startswith(b"\xff\xd8\xff"):
        return True

    #
    # WebP
    #
    if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WEBP":
        return True

    return False


def get_eligible_observations(
    db_path: Path,
    run_id: str,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                h.id,
                h.status_code,
                h.content_type,
                h.title,
                h.screenshot_hash,
                h.context,
                u.url

            FROM http_observations h

            JOIN urls u
              ON u.id = h.url_id

            WHERE h.run_id = ?

            ORDER BY h.id ASC
            """,
            (run_id,),
        ).fetchall()

        output = []

        for row in rows:
            item = dict(row)

            if item.get("screenshot_hash"):
                continue

            status_code = item.get("status_code")

            if status_code is None:
                continue

            
            # keep normal pages, redirects,
            # login pages, forbidden pages, and so on
            
            if not (200 <= status_code <= 499):
                continue

            content_type = (item.get("content_type") or "").lower()

            title = (item.get("title") or "").strip()

            looks_visual = (
                "text/html" in content_type
                or "application/xhtml" in content_type
                or bool(title)
            )

            if not looks_visual:
                continue

            output.append(item)

        return output

    finally:
        connection.close()


def find_generated_image(
    directory: Path,
) -> Path | None:
    """
    Return the largest VALID generated screenshot.

    Zero-byte placeholder images from HTTPX are
    deliberately ignored.
    """

    candidates = []

    for path in directory.rglob("*"):
        if not valid_generated_image(path):
            continue

        candidates.append(path)

    if not candidates:
        return None

    candidates.sort(
        key=lambda item: item.stat().st_size,
        reverse=True,
    )

    return candidates[0]


def describe_invalid_images(
    directory: Path,
) -> list[str]:

    output = []

    for path in directory.rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() not in IMAGE_EXTENSIONS:
            continue

        try:
            size = path.stat().st_size

        except OSError:
            size = -1

        if valid_generated_image(path):
            continue

        try:
            relative = path.relative_to(directory)

        except ValueError:
            relative = path

        output.append((f"{relative} ({size} bytes)"))

    return output


def build_screenshot_command(
    *,
    httpx_path: Path,
    url: str,
    screenshot_timeout_seconds: int,
    idle_seconds: int,
    secret_file: Path | None,
    browser_extension: Path | None,
) -> list[str]:

    command = [
        str(httpx_path),
        "-u",
        url,
        "-silent",
        "-json",
        
        # screenshot mode.
        
        "-ss",
        
        # keep binary screenshot bytes out of JSON output.
        
        "-esb",
        
        # keep headless body content out of JSON output.
        
        "-ehb",
        
        # avoid enormous full-page captures.
        
        "-no-screenshot-full-page",
        
        # browser screenshot timeout.
        
        "-st",
        str(screenshot_timeout_seconds),
        
        # give JS/rendering time to settle.
        
        "-sid",
        str(idle_seconds),
        
        # one target/browser worker.
        
        "-t",
        "1",
        
        # HTTP request timeout.
        
        "-timeout",
        "15",
        
        # preserve the URL's supplied scheme.
        
        "-nfs",
    ]

    if system_chrome_available():
        command.append("-system-chrome")

    if secret_file is not None:
        command.extend(
            [
                "-sf",
                str(secret_file),
            ]
        )

    if browser_extension is not None:
        command.extend(
            [
                "-ho",
                (f"--load-extension={browser_extension}"),
                "-ho",
                (f"--disable-extensions-except={browser_extension}"),
            ]
        )

    return command


def execute_screenshot_command(
    *,
    command: list[str],
    working_directory: Path,
    process_timeout_seconds: int,
) -> subprocess.CompletedProcess:

    return subprocess.run(
        command,
        cwd=str(working_directory),
        capture_output=True,
        text=True,
        timeout=(process_timeout_seconds),
    )


def run_screenshot_capture(
    *,
    url: str,
    temp_root: Path,
    screenshot_timeout_seconds: int = 15,
    idle_seconds: int = 1,
    process_timeout_seconds: int = 120,
    secret_file: Path | None = None,
    browser_extension: Path | None = None,
) -> tuple[
    Path | None,
    str | None,
    tempfile.TemporaryDirectory,
]:

    httpx_path = get_tool_path("httpx")

    temp_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_directory = tempfile.TemporaryDirectory(
        prefix="httpx-shot-",
        dir=str(temp_root),
    )

    working_directory = Path(temporary_directory.name)

    attempts = [
        (
            screenshot_timeout_seconds,
            idle_seconds,
        ),
        
        # one practical retry.
        
        # on HTTPX screenshot fail retry.

        (
            max(
                screenshot_timeout_seconds,
                30,
            ),
            max(
                idle_seconds,
                2,
            ),
        ),
    ]

    last_process = None

    invalid_images = []

    for attempt_number, (
        attempt_timeout,
        attempt_idle,
    ) in enumerate(
        attempts,
        start=1,
    ):
        
        # start retry with a clean HTTPX output so the failed screenshot dosent corrupt the retry
        
        output_directory = working_directory / "output"

        if output_directory.exists():
            shutil.rmtree(
                output_directory,
                ignore_errors=True,
            )

        command = build_screenshot_command(
            httpx_path=httpx_path,
            url=url,
            screenshot_timeout_seconds=(attempt_timeout),
            idle_seconds=(attempt_idle),
            secret_file=(secret_file),
            browser_extension=(browser_extension),
        )

        try:
            last_process = execute_screenshot_command(
                command=command,
                working_directory=(working_directory),
                process_timeout_seconds=(process_timeout_seconds),
            )

        except subprocess.TimeoutExpired:
            if attempt_number == len(attempts):
                return (
                    None,
                    (f"screenshot process timed out after {process_timeout_seconds}s"),
                    temporary_directory,
                )

            continue

        screenshot = find_generated_image(working_directory)

        if screenshot is not None:
            return (
                screenshot,
                None,
                temporary_directory,
            )

        invalid_images = describe_invalid_images(working_directory)

    stdout = ""

    stderr = ""

    return_code = None

    if last_process is not None:
        stdout = (last_process.stdout or "").strip()

        stderr = (last_process.stderr or "").strip()

        return_code = last_process.returncode

    error_parts = []

    if return_code is not None and return_code != 0:
        error_parts.append((f"HTTPX exited with status {return_code}"))

    if invalid_images:
        error_parts.append(
            (
                "HTTPX produced invalid or empty "
                "screenshot image(s): " + ", ".join(invalid_images)
            )
        )

    if stderr:
        error_parts.append(stderr)

    if stdout:
        error_parts.append(stdout)

    if not error_parts:
        error_parts.append(("HTTPX completed without producing a valid screenshot"))

    return (
        None,
        "\n".join(error_parts),
        temporary_directory,
    )


def create_thumbnail(
    source: Path,
    destination: Path,
) -> bool:

    if not valid_generated_image(source):
        return False

    try:
        from PIL import Image

    except ImportError:
        return False

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        with Image.open(source) as image:
            image.thumbnail(
                (
                    480,
                    300,
                ),
                Image.Resampling.LANCZOS,
            )

            if image.mode not in (
                "RGB",
                "L",
            ):
                image = image.convert("RGB")

            elif image.mode == "L":
                image = image.convert("RGB")

            image.save(
                destination,
                format="JPEG",
                quality=72,
                optimize=True,
            )

        return True

    except Exception:
        return False


def store_screenshot(
    *,
    project_root: Path,
    db_path: Path,
    observation_id: int,
    source: Path,
) -> str:
    """
    Store only validated screenshots.

    This second validation is intentional:
    storage should never trust the browser
    capture function blindly.
    """

    if not valid_generated_image(source):
        try:
            size = source.stat().st_size

        except OSError:
            size = -1

        raise RuntimeError(
            (f"Refusing to store invalid screenshot ({size} bytes): {source}")
        )

    screenshot_hash = sha256_file(source)

    extension = source.suffix.lower()

    if extension not in IMAGE_EXTENSIONS:
        extension = ".png"

    relative_path = Path("objects") / "screenshots" / (screenshot_hash + extension)

    destination = project_root / relative_path

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    
    # content-addressed screenshot storage.
    
    if not destination.exists():
        shutil.copy2(
            source,
            destination,
        )

    #
    # Validate again after the copy.
    #
    if not valid_generated_image(destination):
        destination.unlink(missing_ok=True)

        raise RuntimeError(("Stored screenshot copy failed validation."))

    thumbnail_path = (
        project_root / "objects" / "thumbnails" / (screenshot_hash + ".jpg")
    )

    if not thumbnail_path.exists():
        create_thumbnail(
            destination,
            thumbnail_path,
        )

    size_bytes = destination.stat().st_size

    connection = connect(db_path)

    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO objects (
                hash,
                kind,
                relative_path,
                size_bytes,
                compression,
                created_at
            )

            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                screenshot_hash,
                "screenshot",
                str(relative_path),
                size_bytes,
                None,
                now_iso(),
            ),
        )

        connection.execute(
            """
            UPDATE http_observations

            SET screenshot_hash = ?

            WHERE id = ?
            """,
            (
                screenshot_hash,
                observation_id,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return screenshot_hash


def capture_run_screenshots(
    project_slug: str,
    run_id: str,
    auth_profile_id: str | None = None,
) -> dict:

    project = load_project(
        HOME,
        project_slug,
    )

    project_root = project["root"]

    db_path = project["database"]

    observations = get_eligible_observations(
        db_path,
        run_id,
    )

    auth_profile = None

    if auth_profile_id:
        auth_profile = load_auth_profile(
            project_root,
            auth_profile_id,
        )

    summary = {
        "eligible": len(observations),
        "attempted": 0,
        "captured": 0,
        "failed": 0,
    }

    print()

    print("Screenshot pass:")

    print(
        "Browser mode:",
        ("system chrome" if system_chrome_available() else "httpx managed browser"),
    )

    print(f"Eligible pages: {len(observations)}")

    print()

    for index, observation in enumerate(
        observations,
        start=1,
    ):
        url = observation["url"]

        observation_id = observation["id"]

        summary["attempted"] += 1

        print(f"[{index}/{len(observations)}] {url}")

        screenshot = None

        temporary_directory = None

        auth_temp_id = None

        try:
            secret_file = None

            browser_extension = None

            if (
                auth_profile is not None
                and observation.get("context") == auth_context(auth_profile_id)
                and profile_applies_to_target(
                    auth_profile,
                    url,
                )
            ):
                auth_temp_id = f"{run_id}-screenshot-{observation_id}"

                secret_file = write_projectdiscovery_secret_file(
                    project_root,
                    auth_temp_id,
                    auth_profile,
                )

                browser_extension = write_chrome_auth_extension(
                    project_root,
                    auth_temp_id,
                    auth_profile,
                    host=(target_hostname(url)),
                )

            (
                screenshot,
                error,
                temporary_directory,
            ) = run_screenshot_capture(
                url=url,
                temp_root=(project_root / "temp"),
                screenshot_timeout_seconds=15,
                idle_seconds=1,
                process_timeout_seconds=120,
                secret_file=(secret_file),
                browser_extension=(browser_extension),
            )

            if screenshot is None:
                summary["failed"] += 1

                print("  screenshot failed:")

                print(f"  {error}")

                continue

            screenshot_hash = store_screenshot(
                project_root=(project_root),
                db_path=(db_path),
                observation_id=(observation_id),
                source=(screenshot),
            )

            summary["captured"] += 1

            print("  stored:")

            print(f"  {screenshot_hash}")

        except Exception as exc:
            summary["failed"] += 1

            print("  screenshot error:")

            print(f"  {exc}")

        finally:
            if temporary_directory is not None:
                temporary_directory.cleanup()

            if auth_temp_id is not None:
                cleanup_auth_temp(
                    project_root,
                    auth_temp_id,
                )

    print()

    print("Screenshot summary:")

    print(summary)

    return summary


def get_screenshot_path(
    *,
    project_root: Path,
    db_path: Path,
    screenshot_hash: str,
) -> Path | None:

    if not SCREENSHOT_HASH_RE.fullmatch(screenshot_hash):
        return None

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT
                relative_path

            FROM objects

            WHERE
                hash = ?
                AND kind = 'screenshot'
            """,
            (screenshot_hash,),
        ).fetchone()

    finally:
        connection.close()

    if row is None:
        return None

    root_resolved = project_root.resolve()

    path = (project_root / row["relative_path"]).resolve()

    try:
        path.relative_to(root_resolved)

    except ValueError:
        return None

    if not valid_generated_image(path):
        return None

    return path


def get_thumbnail_path(
    *,
    project_root: Path,
    db_path: Path,
    screenshot_hash: str,
) -> Path | None:

    if not SCREENSHOT_HASH_RE.fullmatch(screenshot_hash):
        return None

    thumbnail = project_root / "objects" / "thumbnails" / (screenshot_hash + ".jpg")

    if thumbnail.is_file() and thumbnail.stat().st_size > 0:
        return thumbnail

    return get_screenshot_path(
        project_root=(project_root),
        db_path=(db_path),
        screenshot_hash=(screenshot_hash),
    )
