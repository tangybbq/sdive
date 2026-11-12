"""SQLite ledger: schema and connection."""

from __future__ import annotations

import sqlite3
from pathlib import Path

# Each entry migrates from user_version == index to index + 1. Append only.
MIGRATIONS: list[str] = [
    """
    CREATE TABLE snapshots (
        id          INTEGER PRIMARY KEY,
        project     TEXT NOT NULL,
        sha         TEXT NOT NULL,
        ref         TEXT,
        created_at  TEXT NOT NULL,
        indexed_at  TEXT,
        UNIQUE (project, sha)
    );

    -- Stable identity of a piece of code across snapshots.
    CREATE TABLE units (
        id       INTEGER PRIMARY KEY,
        project  TEXT NOT NULL,
        key      TEXT NOT NULL,
        kind     TEXT NOT NULL CHECK (kind IN ('file', 'function')),
        path     TEXT NOT NULL,
        symbol   TEXT,
        UNIQUE (project, key)
    );

    -- A unit as it exists in one snapshot.
    CREATE TABLE unit_versions (
        snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
        unit_id       INTEGER NOT NULL REFERENCES units(id),
        content_hash  TEXT NOT NULL,
        area          TEXT NOT NULL,
        priority      INTEGER NOT NULL,
        start_line    INTEGER NOT NULL,
        end_line      INTEGER NOT NULL,
        PRIMARY KEY (snapshot_id, unit_id)
    );

    -- A lens is identified by name *and* content: editing it is a new version.
    CREATE TABLE lenses (
        id             INTEGER PRIMARY KEY,
        project        TEXT NOT NULL,
        name           TEXT NOT NULL,
        content_hash   TEXT NOT NULL,
        registered_at  TEXT NOT NULL,
        UNIQUE (project, name, content_hash)
    );

    CREATE TABLE runs (
        id           INTEGER PRIMARY KEY,
        project      TEXT NOT NULL,
        kind         TEXT NOT NULL CHECK (kind IN ('sweep', 'dive', 'verify', 'change')),
        snapshot_id  INTEGER REFERENCES snapshots(id),
        lens_id      INTEGER REFERENCES lenses(id),
        status       TEXT NOT NULL CHECK (status IN ('started', 'recorded', 'abandoned')),
        model        TEXT,
        inputs       TEXT,   -- JSON: hashes of threat model, agent/skill files, etc.
        started_at   TEXT NOT NULL,
        finished_at  TEXT,
        summary      TEXT
    );

    CREATE TABLE run_targets (
        run_id      INTEGER NOT NULL REFERENCES runs(id),
        unit_id     INTEGER REFERENCES units(id),
        finding_id  INTEGER REFERENCES findings(id),
        CHECK ((unit_id IS NULL) != (finding_id IS NULL))
    );
    CREATE INDEX run_targets_run ON run_targets(run_id);

    -- "Unit U, as it read at content_hash, was examined under lens L by run R."
    CREATE TABLE coverage (
        unit_id       INTEGER NOT NULL REFERENCES units(id),
        content_hash  TEXT NOT NULL,
        lens_id       INTEGER REFERENCES lenses(id),
        run_id        INTEGER NOT NULL REFERENCES runs(id),
        status        TEXT NOT NULL CHECK (status IN ('clean', 'hypotheses', 'partial')),
        note          TEXT,
        PRIMARY KEY (unit_id, run_id)
    );
    CREATE INDEX coverage_lookup ON coverage(unit_id, content_hash, lens_id);

    CREATE TABLE findings (
        id             INTEGER PRIMARY KEY,
        project        TEXT NOT NULL,
        slug           TEXT NOT NULL UNIQUE,
        title          TEXT NOT NULL,
        status         TEXT NOT NULL,
        claim          TEXT NOT NULL,
        auditor_notes  TEXT,
        confidence     TEXT,
        property       TEXT,
        attacker       TEXT,
        cwe            TEXT,
        severity       TEXT,
        duplicate_of   TEXT,
        snapshot_id    INTEGER REFERENCES snapshots(id),
        origin_run_id  INTEGER REFERENCES runs(id),
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL
    );

    CREATE TABLE finding_locations (
        finding_id  INTEGER NOT NULL REFERENCES findings(id),
        path        TEXT NOT NULL,
        start_line  INTEGER NOT NULL,
        end_line    INTEGER,
        symbol      TEXT,
        unit_id     INTEGER REFERENCES units(id)
    );

    CREATE TABLE finding_events (
        id           INTEGER PRIMARY KEY,
        finding_id   INTEGER NOT NULL REFERENCES findings(id),
        run_id       INTEGER REFERENCES runs(id),
        at           TEXT NOT NULL,
        from_status  TEXT,
        to_status    TEXT NOT NULL,
        note         TEXT
    );
    """,
    # v2: suspected defects in external (reference) components, for later filing.
    """
    CREATE TABLE upstream_notes (
        id             INTEGER PRIMARY KEY,
        project        TEXT NOT NULL,
        run_id         INTEGER NOT NULL REFERENCES runs(id),
        component      TEXT NOT NULL,
        component_url  TEXT,
        component_sha  TEXT,
        title          TEXT NOT NULL,
        description    TEXT NOT NULL,
        locations      TEXT NOT NULL,   -- JSON list of Location
        status         TEXT NOT NULL DEFAULT 'noted',
        created_at     TEXT NOT NULL
    );
    """,
]


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > len(MIGRATIONS):
        raise RuntimeError(f"database schema v{version} is newer than this sdive")
    for i in range(version, len(MIGRATIONS)):
        conn.executescript(f"BEGIN;\n{MIGRATIONS[i]}\nPRAGMA user_version = {i + 1};\nCOMMIT;")
