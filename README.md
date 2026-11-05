# Reconmancer

[![CI](https://github.com/minerlord82/Reconmancer/actions/workflows/ci.yml/badge.svg)](https://github.com/minerlord82/Reconmancer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Reconmancer is a lightweight web workspace for **authorized bug-bounty reconnaissance**. It coordinates ProjectDiscovery HTTPX, Katana, and Nuclei while keeping raw output, normalized SQLite data, redirect relationships, handoff provenance, evidence, findings, and analysis state isolated per project.

Reconmancer is intended only for systems you own or are explicitly authorized to test.

## What it includes

- Multi-project workspace with isolated SQLite databases and project storage.
- HTTPX reconnaissance with redirect tracking and optional Chromium-backed screenshots.
- Katana standard, headless, and deep crawling profiles.
- Nuclei HTTP/SSL scanning with configurable conservative defaults.
- Anonymous-by-default scans plus exact-host authentication profiles.
- Persistent and selective handoffs between HTTPX, Katana, and Nuclei.
- Request/response traffic evidence with common credential-header redaction.
- Findings and evidence investigation workspace.
- Endpoint clustering and query-parameter analysis.
- Job recovery/watchdog support with partial-result preservation.
- Optional gzip/zstd maintenance for older raw output.
- Storage cleanup and full collected-data reset controls.
- Settings page showing installed HTTPX/Katana/Nuclei versions directly from the configured binaries.
- Manual ProjectDiscovery tool updates through PDTM when available.
- Manual management of a separate ProjectDiscovery `nuclei-templates` checkout.

## Current deployment layout

Reconmancer v0.1.4 currently expects its application root to be:

```text
/opt/reconmancer/
```

The source contains this path in the runtime code, so install the project there unless you intentionally refactor the application root.

The expected layout is:

```text
/opt/reconmancer/
├── config/
│   ├── tools.example.yaml
│   └── tools.yaml              # local only; not committed
├── projects/                   # runtime project data; not committed
├── reconmancer/
├── scripts/
├── templates/                  # managed external template checkout lives here
├── requirements.txt
└── venv/                       # local only; not committed
```

## Requirements

- Linux environment; the current deployment has been developed for a Kali/Debian-style VPS.
- Python 3.11+.
- Python packages from `requirements.txt`.
- ProjectDiscovery `httpx`, `katana`, and `nuclei`.
- Chromium/Chrome for HTTPX screenshots and browser-backed crawling.
- `git` for the managed ProjectDiscovery `nuclei-templates` checkout.
- PDTM if you want to use the in-app **Update** buttons for HTTPX, Katana, and Nuclei.
- Optional `zstd` executable when zstd compression is enabled. Gzip support uses Python's standard library.

The source archive does **not** bundle ProjectDiscovery binaries, Chromium, PDTM, or `nuclei-templates`.

## Installation

For a fresh Kali/Debian-style system, use the bundled installer from the extracted source directory:

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer places Reconmancer at `/opt/reconmancer`, creates the Python virtual environment, installs the required system packages, installs current stable Go, installs PDTM plus HTTPX/Katana/Nuclei, writes `config/tools.yaml`, installs Chromium, and prepares the separately managed ProjectDiscovery `nuclei-templates` checkout. It deliberately does **not** create a systemd service or expose the application publicly.

After installation:

```bash
cd /opt/reconmancer
source venv/bin/activate
python -m reconmancer.main
```

For manual/custom installations, copy `config/tools.example.yaml` to `config/tools.yaml` and point each entry at the exact HTTPX, Katana, and Nuclei executables you want Reconmancer to use.

Run the optional self-check with:

```bash
cd /opt/reconmancer
source venv/bin/activate
python -m scripts.reconmancer_selfcheck
```

Reconmancer binds to `127.0.0.1:8000` and is not intended to be exposed directly to the public Internet.

For a remote VPS, a typical local SSH tunnel is:

```bash
ssh -L 8000:127.0.0.1:8000 USER@YOUR_VPS_IP
```

Then open:

```text
http://127.0.0.1:8000
```

## First project

Open the landing page and create a project. A new project receives its own configuration, database, input staging, raw engine output, objects, logs, temporary data, and authentication-profile directory.

The default disk budget is 10 GB and can be changed per project.

Project data is stored under:

```text
/opt/reconmancer/projects/<project-slug>/
```

The repository `.gitignore` excludes project directories from source control.

## Visual identity

Reconmancer v0.1.4 introduces **The Arcane Atlas**, a panoramic illustrated UI inspired by the supplied concept screenshot. A full-screen local WebP fantasy landscape replaces the flat page background; the sidebar shows a moonlit fortress scene; overview statistics appear in a rune-framed ledger; storage has a lantern scene; and HTTPX/Katana/Nuclei have distinct illustrated panels. Secondary pages inherit the same sidebar, scenic page headers, carved panel borders and responsive layout. The top banner uses a non-cropping image. At narrow widths, a separate mobile banner preserves readability.

Only the shared `base.html`, the landing and overview templates, a new CSS layer, and local lightweight art assets are required for this change. **No Python engine, worker, scan command, Flask route, persistence, or existing JavaScript source is changed.** See `REDESIGN_v0.1.4.md` for the exact file list and upgrade instructions.

## Screenshots

HTTPX screenshots use HTTPX headless screenshot mode. When a local Chromium/Chrome installation is available, Reconmancer uses system Chrome.

Screenshot objects are validated before they are accepted into content-addressed storage. Empty or invalid image placeholders are rejected instead of being recorded as successful screenshots.

Pillow is used for thumbnail generation.

## Nuclei templates

Reconmancer supports two Nuclei template-source behaviors during scans:

- **Default Nuclei**: allow Nuclei to resolve its normal/default templates.
- **nuclei-templates (ProjectDiscovery)**: explicitly use Reconmancer's separately managed checkout under `templates/nuclei-templates-projectdiscovery/`.

That managed checkout is intentionally excluded from the source archive and Git. Use **Settings → Update Nuclei Templates** to clone or update it manually. Reconmancer does not run a background template updater.

The Settings page displays the human-readable ProjectDiscovery release version for the managed checkout rather than exposing the Git revision as the primary version label.

## Tool versions and updates

Settings reads the HTTPX, Katana, and Nuclei versions from the exact executables configured in `config/tools.yaml`; the displayed engine versions are not hardcoded.

If PDTM is installed, Reconmancer can manually update each configured ProjectDiscovery tool from Settings. Updates are refused while a job for that engine is queued or running.

## Authentication safety model

Reconmancer scans anonymously by default.

Authentication profiles are explicit and bound to exact hostnames. For example, authorizing `example.com` does not automatically authorize `api.example.com`. Credential-bearing browser or engine configuration is created only for approved targets and temporary auth material is cleaned up after use.

Authentication profiles are stored inside project runtime data and must never be committed to a public repository.

## Storage cleanup

The Storage page can remove collected scan/investigation data while preserving project configuration, the project's target file, and authentication profiles.

Deleting a project removes that complete project directory. Active-job checks are used before destructive project operations.