from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from reconmancer.core.database import connect
from reconmancer.core.tooling import get_tool_path


HOME = Path("/opt/reconmancer")
PROJECTDISCOVERY_REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
VERSION_CACHE_FILENAME = ".reconmancer-release-version"

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
VERSION_RE = re.compile(r"\bv\d+(?:\.\d+)+(?:[-+][A-Za-z0-9._-]+)?\b")
RELEASE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def _clean_output(value: str) -> str:
    value = ANSI_RE.sub("", value or "")
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return "\n".join(lines)


def default_nuclei_status() -> dict:
    """Describe the template set Nuclei resolves by default."""

    try:
        nuclei_path = get_tool_path("nuclei")
        result = subprocess.run(
            [str(nuclei_path), "-tv", "-duc", "-nc"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, RuntimeError, KeyError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "version": "Unavailable",
            "detail": str(exc),
            "label": "Default Nuclei",
        }

    output = _clean_output(result.stdout + "\n" + result.stderr)
    match = VERSION_RE.search(output)
    version = (
        match.group(0) if match else (output.splitlines()[0] if output else "Unknown")
    )

    return {
        "ok": result.returncode == 0,
        "version": version,
        "detail": output[:2000],
        "label": "Default Nuclei",
    }


def projectdiscovery_repo_path(home: Path = HOME) -> Path:
    return home / "templates" / "nuclei-templates-projectdiscovery"


def _git_output(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def _release_version_key(value: str) -> tuple[int, int, int]:
    match = RELEASE_TAG_RE.fullmatch(value.strip())
    if not match:
        return (-1, -1, -1)
    return tuple(int(part) for part in match.groups())


def _version_cache_path(path: Path) -> Path:
    return path / VERSION_CACHE_FILENAME


def _read_cached_release_version(path: Path) -> str | None:
    cache = _version_cache_path(path)
    try:
        value = cache.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value if RELEASE_TAG_RE.fullmatch(value) else None


def _write_cached_release_version(path: Path, version: str) -> None:
    if not RELEASE_TAG_RE.fullmatch(version):
        return
    cache = _version_cache_path(path)
    temporary = cache.with_suffix(cache.suffix + ".tmp")
    temporary.write_text(version + "\n", encoding="utf-8")
    temporary.replace(cache)


def _latest_remote_release_version(path: Path) -> str | None:
    """
    Return the newest official vX.Y.Z release tag from origin without requiring
    local tag history. This works with Reconmancer's intentionally shallow clone.
    """

    result = _git_output(
        [
            "git",
            "-C",
            str(path),
            "ls-remote",
            "--tags",
            "--refs",
            "origin",
            "refs/tags/v*",
        ],
        timeout=30,
    )

    if result.returncode != 0:
        return None

    versions: list[str] = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        try:
            _object_id, ref = line.split(None, 1)
        except ValueError:
            continue

        prefix = "refs/tags/"
        if not ref.startswith(prefix):
            continue

        tag = ref[len(prefix) :].strip()
        if RELEASE_TAG_RE.fullmatch(tag):
            versions.append(tag)

    if not versions:
        return None

    return max(versions, key=_release_version_key)


def _release_version(path: Path, *, refresh: bool = False) -> str:
    """
    Return the human-readable ProjectDiscovery release version.

    The managed repo is shallow, so local `git describe` may have no tags.
    Reconmancer therefore caches the latest official remote release tag when
    templates are installed/updated. Settings reads the cache instantly.
    """

    if not refresh:
        cached = _read_cached_release_version(path)
        if cached:
            return cached

    remote = _latest_remote_release_version(path)
    if remote:
        try:
            _write_cached_release_version(path, remote)
        except OSError:
            pass
        return remote

    cached = _read_cached_release_version(path)
    return cached or "Unknown"


def projectdiscovery_template_status(home: Path = HOME) -> dict:
    path = projectdiscovery_repo_path(home)

    if not path.is_dir() or not (path / ".git").is_dir():
        return {
            "ok": False,
            "installed": False,
            "label": "nuclei-templates (ProjectDiscovery)",
            "version": "Not installed",
            "revision": "—",
            "branch": "—",
            "path": str(path),
            "detail": "Use the Update Nuclei Templates button to clone the official ProjectDiscovery repository.",
        }

    try:
        revision_result = _git_output(
            ["git", "-C", str(path), "rev-parse", "--short=12", "HEAD"]
        )
        branch_result = _git_output(
            ["git", "-C", str(path), "branch", "--show-current"]
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "installed": True,
            "label": "nuclei-templates (ProjectDiscovery)",
            "version": _read_cached_release_version(path) or "Unknown",
            "revision": "Unknown",
            "branch": "Unknown",
            "path": str(path),
            "detail": str(exc),
        }

    revision = _clean_output(revision_result.stdout) or "Unknown"
    branch = _clean_output(branch_result.stdout) or "Unknown"
    version = _release_version(path)

    ok = revision_result.returncode == 0
    detail = _clean_output(revision_result.stderr + "\n" + branch_result.stderr)

    return {
        "ok": ok,
        "installed": True,
        "label": "nuclei-templates (ProjectDiscovery)",
        "version": version,
        "revision": revision,
        "branch": branch,
        "path": str(path),
        "detail": detail[:2000],
    }


def _project_databases(home: Path) -> list[Path]:
    projects_root = home / "projects"

    if not projects_root.is_dir():
        return []

    output: list[Path] = []

    for entry in projects_root.iterdir():
        db_path = entry / "recon.db"
        if db_path.is_file():
            output.append(db_path)

    return output


def active_nuclei_jobs(home: Path) -> list[dict]:
    """Find queued/running Nuclei jobs across all Reconmancer projects."""

    active: list[dict] = []

    for db_path in _project_databases(home):
        connection = None

        try:
            connection = connect(db_path)
            rows = connection.execute(
                """
                SELECT id, status, run_id
                FROM jobs
                WHERE engine = 'nuclei'
                  AND status IN ('queued', 'running')
                ORDER BY created_at ASC
                """
            ).fetchall()

            for row in rows:
                item = dict(row)
                item["project"] = db_path.parent.name
                active.append(item)

        except Exception:
            continue

        finally:
            if connection is not None:
                connection.close()

    return active


def update_projectdiscovery_templates(home: Path) -> dict:
    """
    Manually clone/update ProjectDiscovery's official nuclei-templates repo.

    This managed checkout is separate from whatever template directory Nuclei
    itself resolves by default. Reconmancer never updates it automatically.
    """

    active = active_nuclei_jobs(home)

    if active:
        jobs = ", ".join(f"{item['project']}:{item['id']}" for item in active[:8])
        raise RuntimeError(
            "Cannot update nuclei-templates (ProjectDiscovery) while a Nuclei scan is active. "
            f"Active job(s): {jobs}"
        )

    if shutil.which("git") is None:
        raise RuntimeError("git is not installed or not available in PATH.")

    path = projectdiscovery_repo_path(home)
    before_status = projectdiscovery_template_status(home)
    before_version = before_status.get("version", "Not installed")
    before_revision = before_status.get("revision", "—")

    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if not (path / ".git").is_dir():
            if path.exists() and any(path.iterdir()):
                raise RuntimeError(
                    f"Template destination already exists but is not a managed git repository: {path}"
                )

            result = _git_output(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    PROJECTDISCOVERY_REPO_URL,
                    str(path),
                ],
                timeout=600,
            )
        else:
            remote_result = _git_output(
                ["git", "-C", str(path), "remote", "get-url", "origin"]
            )
            remote = _clean_output(remote_result.stdout)
            if (
                remote_result.returncode != 0
                or "projectdiscovery/nuclei-templates" not in remote.lower()
            ):
                raise RuntimeError(
                    "The managed template directory does not point to ProjectDiscovery/nuclei-templates."
                )

            branch_result = _git_output(
                ["git", "-C", str(path), "branch", "--show-current"]
            )
            branch = _clean_output(branch_result.stdout) or "main"

            result = _git_output(
                [
                    "git",
                    "-C",
                    str(path),
                    "fetch",
                    "--depth",
                    "1",
                    "origin",
                    branch,
                ],
                timeout=600,
            )

            if result.returncode == 0:
                result = _git_output(
                    ["git", "-C", str(path), "reset", "--hard", "FETCH_HEAD"],
                    timeout=60,
                )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "ProjectDiscovery nuclei-templates update timed out after 10 minutes."
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Could not run git: {exc}") from exc

    output = _clean_output(result.stdout + "\n" + result.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            "ProjectDiscovery nuclei-templates update failed. "
            + (output[:1500] if output else f"exit status {result.returncode}")
        )

    # Refresh the cached human-readable release version only when the user
    # explicitly performs a manual template update.
    release_version = _release_version(path, refresh=True)
    after_status = projectdiscovery_template_status(home)
    after_revision = after_status.get("revision", "Unknown")

    return {
        "before": before_version,
        "after": release_version,
        "before_revision": before_revision,
        "after_revision": after_revision,
        "path": str(path),
        "output": output,
    }
