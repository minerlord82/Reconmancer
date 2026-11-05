from __future__ import annotations

from pathlib import Path

from reconmancer.core.database import connect


SCHEMA = """
CREATE TABLE IF NOT EXISTS nuclei_findings (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    run_id TEXT NOT NULL,

    fingerprint TEXT NOT NULL,

    template_id TEXT,
    template_path TEXT,

    matcher_name TEXT,

    name TEXT,
    severity TEXT,

    protocol TEXT,

    host TEXT,
    url TEXT,
    matched_at TEXT,

    ip TEXT,
    port TEXT,

    tags_json TEXT,
    authors_json TEXT,

    description TEXT,

    references_json TEXT,

    cve_json TEXT,
    cwe_json TEXT,

    cvss_score REAL,
    cvss_metrics TEXT,

    extracted_results_json TEXT,

    timestamp TEXT,

    created_at TEXT NOT NULL,

    FOREIGN KEY(run_id)
        REFERENCES runs(id)
        ON DELETE CASCADE,

    UNIQUE(
        run_id,
        fingerprint
    )
);


CREATE INDEX IF NOT EXISTS
idx_nuclei_findings_run
ON nuclei_findings(run_id);


CREATE INDEX IF NOT EXISTS
idx_nuclei_findings_severity
ON nuclei_findings(
    run_id,
    severity
);


CREATE INDEX IF NOT EXISTS
idx_nuclei_findings_template
ON nuclei_findings(
    template_id
);


CREATE INDEX IF NOT EXISTS
idx_nuclei_findings_host
ON nuclei_findings(
    host
);


CREATE INDEX IF NOT EXISTS
idx_nuclei_findings_matched
ON nuclei_findings(
    matched_at
);
"""


def ensure_nuclei_schema(
    db_path: Path,
) -> None:

    connection = connect(db_path)

    try:
        connection.executescript(SCHEMA)

        connection.commit()

    finally:
        connection.close()
