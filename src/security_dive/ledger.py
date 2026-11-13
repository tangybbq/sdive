"""Ledger operations: snapshots, unit index, lenses, the work queue, recording."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from . import repo
from .config import Config, ConfigError, Project
from .schemas import AuditResult, VerifyResult
from .units import Unit

LEASE = timedelta(hours=12)
UNIT_KINDS = ("sweep", "dive")
COVERED = ("clean", "hypotheses")

# Allowed finding status transitions (manual `finding set` and verify runs).
TRANSITIONS: dict[str, set[str]] = {
    "hypothesis": {"hypothesis", "verified", "rejected", "duplicate"},
    "verified": {"exported", "fixed", "rejected", "duplicate"},
    "rejected": {"hypothesis"},
    "duplicate": {"hypothesis"},
    "exported": {"fixed"},
    "fixed": set(),
}


class LedgerError(Exception):
    pass


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:32]


# --- snapshots and units ---------------------------------------------------


def snapshot_id(conn: sqlite3.Connection, project: str, sha: str, ref: str | None = None) -> int:
    with conn:
        conn.execute(
            "INSERT INTO snapshots (project, sha, ref, created_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (project, sha) DO UPDATE SET ref = coalesce(excluded.ref, ref)",
            (project, sha, ref, now()),
        )
    return conn.execute(
        "SELECT id FROM snapshots WHERE project = ? AND sha = ?", (project, sha)
    ).fetchone()[0]


def indexed_snapshot(conn: sqlite3.Connection, project: str, sha: str) -> int:
    row = conn.execute(
        "SELECT id, indexed_at FROM snapshots WHERE project = ? AND sha = ?", (project, sha)
    ).fetchone()
    if row is None or row["indexed_at"] is None:
        raise LedgerError(f"{project}@{sha[:12]} is not indexed; run `sdive units {project}`")
    return row["id"]


def index_units(conn: sqlite3.Connection, project: str, snap: int, units: list[Unit]) -> None:
    """Replace the snapshot's unit_versions with `units` (coverage is unaffected)."""
    with conn:
        conn.execute("DELETE FROM unit_versions WHERE snapshot_id = ?", (snap,))
        for u in units:
            unit_id = conn.execute(
                "INSERT INTO units (project, key, kind, path, symbol) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (project, key) DO UPDATE SET path = excluded.path, "
                "symbol = excluded.symbol RETURNING id",
                (project, u.key, u.kind, u.path, u.symbol),
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO unit_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (snap, unit_id, u.content_hash, u.area, u.priority, u.start_line, u.end_line),
            )
        conn.execute("UPDATE snapshots SET indexed_at = ? WHERE id = ?", (now(), snap))


# --- lenses ----------------------------------------------------------------


def lens_path(project: Project, name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise LedgerError(f"invalid lens name {name!r}")
    return project.lenses_dir / f"{name}.md"


def register_lens(conn: sqlite3.Connection, project: Project, name: str) -> int:
    """The lens id for the lens file's *current* content."""
    path = lens_path(project, name)
    if not path.is_file():
        raise LedgerError(f"no lens {name!r} for {project.name} (expected {path})")
    h = file_hash(path)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO lenses (project, name, content_hash, registered_at) "
            "VALUES (?, ?, ?, ?)",
            (project.name, name, h, now()),
        )
    return conn.execute(
        "SELECT id FROM lenses WHERE project = ? AND name = ? AND content_hash = ?",
        (project.name, name, h),
    ).fetchone()[0]


def available_lenses(project: Project) -> list[str]:
    if not project.lenses_dir.is_dir():
        return []
    return sorted(p.stem for p in project.lenses_dir.glob("*.md"))


# --- the queue -------------------------------------------------------------


def _lease_cutoff() -> str:
    return (datetime.now(UTC) - LEASE).isoformat(timespec="seconds")


def _uncovered_units(
    conn: sqlite3.Connection,
    project: str,
    snap: int,
    lens_id: int,
    kind: str,
    area: str | None,
) -> list[sqlite3.Row]:
    """Function units in the snapshot not yet covered under (lens, run kind), and
    not leased by a recent started run of the same kind and lens."""
    sql = """
        SELECT u.id, u.key, u.path, u.symbol, uv.area, uv.priority,
               uv.start_line, uv.end_line
        FROM unit_versions uv JOIN units u ON u.id = uv.unit_id
        WHERE uv.snapshot_id = :snap AND u.kind = 'function'
          AND (:area IS NULL OR uv.area = :area)
          AND NOT EXISTS (
              SELECT 1 FROM coverage c JOIN runs r ON r.id = c.run_id
              WHERE c.unit_id = uv.unit_id AND c.content_hash = uv.content_hash
                AND c.lens_id = :lens AND r.kind = :kind
                AND c.status IN ('clean', 'hypotheses'))
          AND NOT EXISTS (
              SELECT 1 FROM run_targets t JOIN runs r ON r.id = t.run_id
              WHERE t.unit_id = uv.unit_id AND r.status = 'started'
                AND r.kind = :kind AND r.lens_id = :lens
                AND r.project = :project AND r.started_at > :cutoff)
        ORDER BY uv.priority DESC, u.path, uv.start_line
    """
    return conn.execute(
        sql,
        {"snap": snap, "area": area, "lens": lens_id, "kind": kind,
         "project": project, "cutoff": _lease_cutoff()},
    ).fetchall()


def _start_run(
    conn: sqlite3.Connection,
    project: Project,
    kind: str,
    snap: int | None,
    lens_id: int | None,
    unit_ids: list[int] = (),
    finding_ids: list[int] = (),
) -> int:
    inputs = {}
    if project.threat_model and project.threat_model.is_file():
        inputs["threat_model"] = file_hash(project.threat_model)
    with conn:
        run_id = conn.execute(
            "INSERT INTO runs (project, kind, snapshot_id, lens_id, status, inputs, started_at) "
            "VALUES (?, ?, ?, ?, 'started', ?, ?) RETURNING id",
            (project.name, kind, snap, lens_id, json.dumps(inputs), now()),
        ).fetchone()[0]
        conn.executemany(
            "INSERT INTO run_targets (run_id, unit_id) VALUES (?, ?)",
            [(run_id, u) for u in unit_ids],
        )
        conn.executemany(
            "INSERT INTO run_targets (run_id, finding_id) VALUES (?, ?)",
            [(run_id, f) for f in finding_ids],
        )
    return run_id


DIVE_MAX_LINES = 600
SWEEP_MAX_LINES = 3000


def _batch(rows: list, kind: str, max_units: int, max_lines: int | None) -> list:
    """The targets of the next run, from uncovered `rows` in queue order.

    A dive takes uncovered functions of one file (the first with work left), in
    line order, up to `max_units` functions and `max_lines` lines, so each dive
    stays deep. A sweep takes whole areas in priority order up to `max_lines`
    lines, so cross-file reasoning within an area is kept while one pass stays
    small enough to read properly. Both always take at least one unit/area.
    """
    def size(r) -> int:
        return r["end_line"] - r["start_line"] + 1
    if kind == "dive":
        limit = max_lines or DIVE_MAX_LINES
        path = rows[0]["path"]
        batch, lines = [], 0
        for r in (r for r in rows if r["path"] == path):
            if batch and (len(batch) >= max_units or lines + size(r) > limit):
                break
            batch.append(r)
            lines += size(r)
        return batch
    limit = max_lines or SWEEP_MAX_LINES
    areas: dict[str, list] = {}
    for r in rows:
        areas.setdefault(r["area"], []).append(r)
    batch, lines = [], 0
    for members in areas.values():
        n = sum(size(r) for r in members)
        if batch and lines + n > limit:
            break
        batch.extend(members)
        lines += n
    return batch


def next_unit_run(
    conn: sqlite3.Connection,
    project: Project,
    snap: int,
    kind: str,
    lens: str,
    area: str | None = None,
    max_units: int = 40,
    max_lines: int | None = None,
) -> int | None:
    """Start a sweep or dive run on the highest-priority uncovered work (see
    `_batch` for how much one run takes)."""
    if kind not in UNIT_KINDS:
        raise LedgerError(f"not a unit run kind: {kind}")
    if area is not None:
        project.area_named(area)
    lens_id = register_lens(conn, project, lens)
    rows = _uncovered_units(conn, project.name, snap, lens_id, kind, area)
    if not rows:
        return None
    if kind == "dive":
        rows = _prefer_idle_area(conn, project.name, snap, lens_id, rows)
    rows = _batch(rows, kind, max_units, max_lines)
    return _start_run(conn, project, kind, snap, lens_id, unit_ids=[r["id"] for r in rows])


def _prefer_idle_area(conn: sqlite3.Connection, project: str, snap: int, lens_id: int,
                      rows: list) -> list:
    """With dives in flight, start the next one in an area none of them is in.

    Parallel runs only see each other's dossier notes once recorded, so two
    concurrent dives in one area can't build on (or deduplicate against) each
    other. Spreading them across areas avoids that; with no idle area left the
    queue order stands. Sequential runs are unaffected.
    """
    busy = {r[0] for r in conn.execute(
        """SELECT DISTINCT uv.area FROM run_targets t JOIN runs r ON r.id = t.run_id
           JOIN unit_versions uv ON uv.unit_id = t.unit_id AND uv.snapshot_id = :snap
           WHERE r.status = 'started' AND r.kind = 'dive' AND r.lens_id = :lens
             AND r.project = :project AND r.started_at > :cutoff""",
        {"snap": snap, "lens": lens_id, "project": project, "cutoff": _lease_cutoff()})}
    if not busy:
        return rows
    idle = [r for r in rows if r["area"] not in busy]
    if not idle:
        return rows
    return idle + [r for r in rows if r["area"] in busy]


def queue_estimate(
    conn: sqlite3.Connection,
    project: Project,
    snap: int,
    kind: str,
    lens: str,
    area: str | None = None,
    max_units: int = 40,
    max_lines: int | None = None,
) -> list[dict]:
    """Simulate the queue: the runs `next` would hand out, in order, until the
    work under (kind, lens) is done. Leased targets are excluded, as in `next`."""
    if area is not None:
        project.area_named(area)
    lens_id = register_lens(conn, project, lens)
    rows = list(_uncovered_units(conn, project.name, snap, lens_id, kind, area))
    runs = []
    while rows:
        batch = _batch(rows, kind, max_units, max_lines)
        taken = {r["id"] for r in batch}
        runs.append({
            "areas": list(dict.fromkeys(r["area"] for r in batch)),
            "paths": list(dict.fromkeys(r["path"] for r in batch)),
            "functions": len(batch),
            "lines": sum(r["end_line"] - r["start_line"] + 1 for r in batch),
        })
        rows = [r for r in rows if r["id"] not in taken]
    return runs


DEFAULT_MINUTES = {"dive": 3.0, "sweep": 8.0, "verify": 2.0}


def run_minutes(conns: list[sqlite3.Connection], project: str) -> dict[str, tuple[float, int]]:
    """Median minutes per recorded run of each kind, pooled over `conns` (every
    ledger), with the sample size; DEFAULT_MINUTES where there is no history.
    Run time is a usable proxy for cost: both follow the tokens processed."""
    samples: dict[str, list[float]] = {k: [] for k in DEFAULT_MINUTES}
    for conn in conns:
        for r in conn.execute(
                "SELECT kind, (julianday(finished_at) - julianday(started_at)) * 1440 AS m "
                "FROM runs WHERE project = ? AND status = 'recorded' AND finished_at IS NOT NULL",
                (project,)):
            if r["kind"] in samples and r["m"] is not None and r["m"] > 0:
                samples[r["kind"]].append(r["m"])
    out = {}
    for kind, xs in samples.items():
        if xs:
            xs.sort()
            mid = len(xs) // 2
            out[kind] = ((xs[mid] if len(xs) % 2 else (xs[mid - 1] + xs[mid]) / 2), len(xs))
        else:
            out[kind] = (DEFAULT_MINUTES[kind], 0)
    return out


def next_verify_run(conn: sqlite3.Connection, project: Project) -> int | None:
    """Start a verify run on the oldest unleased hypothesis."""
    row = conn.execute(
        """
        SELECT f.id, f.snapshot_id FROM findings f
        WHERE f.project = :project AND f.status = 'hypothesis'
          AND NOT EXISTS (
              SELECT 1 FROM run_targets t JOIN runs r ON r.id = t.run_id
              WHERE t.finding_id = f.id AND r.status = 'started' AND r.started_at > :cutoff)
        ORDER BY f.created_at, f.id LIMIT 1
        """,
        {"project": project.name, "cutoff": _lease_cutoff()},
    ).fetchone()
    if row is None:
        return None
    return _start_run(conn, project, "verify", row["snapshot_id"], None, finding_ids=[row["id"]])


def get_run(conn: sqlite3.Connection, run_id: int) -> sqlite3.Row:
    run = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        raise LedgerError(f"no run {run_id}")
    return run


def abandon(conn: sqlite3.Connection, run_id: int) -> None:
    run = get_run(conn, run_id)
    if run["status"] != "started":
        raise LedgerError(f"run {run_id} is {run['status']}, not started")
    with conn:
        conn.execute(
            "UPDATE runs SET status = 'abandoned', finished_at = ? WHERE id = ?", (now(), run_id)
        )


# --- briefs ----------------------------------------------------------------


def _finding_locations(conn: sqlite3.Connection, finding_id: int) -> list[dict]:
    return [
        {k: r[k] for k in ("path", "start_line", "end_line", "symbol")}
        for r in conn.execute(
            "SELECT * FROM finding_locations WHERE finding_id = ? ORDER BY rowid", (finding_id,)
        )
    ]


REFERENCE_NOTE = (
    "Reference trees are external components (e.g. crypto libraries) for establishing "
    "API contracts: search their headers rather than reading them whole, and do not "
    "audit them. Claims that depend on a library's behaviour should name the version "
    "relied on. A defect inside a reference tree goes in upstream_notes, not hypotheses."
)


def agent_for(kind: str) -> str:
    return "sdive-verifier" if kind == "verify" else "sdive-auditor"


def brief_path(cfg: Config, run_id: int) -> Path:
    return cfg.staging / f"run-{run_id}.brief.json"


def write_brief(conn: sqlite3.Connection, cfg: Config, run_id: int) -> dict:
    """Write the run's brief to staging (the subagent reads it from there)."""
    b = brief(conn, cfg, run_id)
    path = brief_path(cfg, run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(b, indent=2) + "\n")
    return b


def _snapshot_references(conn: sqlite3.Connection, cfg: Config, run: sqlite3.Row) -> list[dict]:
    snap = conn.execute("SELECT sha FROM snapshots WHERE id = ?", (run["snapshot_id"],)).fetchone()
    if snap is None:
        return []
    tree = cfg.snapshot_path(run["project"], snap["sha"])
    return repo.read_marker(tree).get("references", [])


def brief(conn: sqlite3.Connection, cfg: Config, run_id: int) -> dict:
    """Everything a subagent needs for one run, as JSON-able data."""
    run = get_run(conn, run_id)
    project = cfg.project(run["project"])
    snap = conn.execute("SELECT * FROM snapshots WHERE id = ?", (run["snapshot_id"],)).fetchone()
    out: dict = {
        "run_id": run_id,
        "kind": run["kind"],
        "status": run["status"],
        "project": project.name,
        "snapshot": {
            "sha": snap["sha"],
            "path": str(cfg.snapshot_path(project.name, snap["sha"])),
        } if snap else None,
        "threat_model": str(project.threat_model) if project.threat_model else None,
        "ledger": cfg.ledger,
        "agent": agent_for(run["kind"]),
        "brief_path": str(brief_path(cfg, run_id)),
        "result_path": str(cfg.staging / f"run-{run_id}.json"),
        "result_schema": "verify" if run["kind"] == "verify" else "audit",
        "record_command": f"uv run sdive --ledger {cfg.ledger} record {run_id}",
    }
    refs = _snapshot_references(conn, cfg, run)
    if refs:
        tree = cfg.snapshot_path(project.name, snap["sha"])
        out["references"] = [
            {"path": str(tree / r["path"]), "repo_path": r["path"], "name": r["name"],
             "sha": r["sha"], "role": r["role"]}
            for r in refs
        ]
        out["reference_note"] = REFERENCE_NOTE
    if run["lens_id"] is not None:
        lens = conn.execute("SELECT * FROM lenses WHERE id = ?", (run["lens_id"],)).fetchone()
        path = lens_path(project, lens["name"])
        out["lens"] = {
            "name": lens["name"], "path": str(path), "content_hash": lens["content_hash"]
        }
        if path.is_file() and file_hash(path) != lens["content_hash"]:
            out["lens"]["warning"] = "lens file changed since this run started"
    targets = conn.execute(
        """
        SELECT u.key, u.path, u.symbol, uv.area, uv.start_line, uv.end_line
        FROM run_targets t JOIN units u ON u.id = t.unit_id
        JOIN unit_versions uv ON uv.unit_id = u.id AND uv.snapshot_id = ?
        WHERE t.run_id = ? ORDER BY u.path, uv.start_line
        """,
        (run["snapshot_id"], run_id),
    ).fetchall()
    if targets:
        out["targets"] = [dict(t) for t in targets]
        areas = sorted({t["area"] for t in targets})
        out["dossiers"] = {a: str(cfg.dossier_path(project.name, a)) for a in areas}
    frow = conn.execute(
        "SELECT f.* FROM run_targets t JOIN findings f ON f.id = t.finding_id WHERE t.run_id = ?",
        (run_id,),
    ).fetchone()
    if frow is not None:
        # Blind: confidence and auditor_notes are deliberately withheld.
        locs = _finding_locations(conn, frow["id"])
        out["finding"] = {
            "slug": frow["slug"],
            "title": frow["title"],
            "claim": frow["claim"],
            "locations": locs,
            "claimed_property": frow["property"],
            "claimed_attacker": frow["attacker"],
            "claimed_cwe": frow["cwe"],
        }
        areas = sorted({project.area_for(loc["path"]).name for loc in locs})
        out["dossiers"] = {a: str(cfg.dossier_path(project.name, a)) for a in areas}
    return out


# --- recording -------------------------------------------------------------


@dataclass
class RecordReport:
    run_id: int
    kind: str
    covered: int = 0
    partial: int = 0
    missing: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    verdict: str | None = None
    dossiers: list[str] = field(default_factory=list)
    upstream: list[str] = field(default_factory=list)


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:48].rstrip("-") or "finding"


def _unique_slug(conn: sqlite3.Connection, base: str) -> str:
    slug, n = base, 1
    while conn.execute("SELECT 1 FROM findings WHERE slug = ?", (slug,)).fetchone():
        n += 1
        slug = f"{base}-{n}"
    return slug


def _unit_at(conn: sqlite3.Connection, snap: int, path: str, line: int) -> int | None:
    """Innermost unit (function before file) containing path:line in the snapshot."""
    row = conn.execute(
        """
        SELECT u.id FROM unit_versions uv JOIN units u ON u.id = uv.unit_id
        WHERE uv.snapshot_id = ? AND u.path = ? AND uv.start_line <= ? AND uv.end_line >= ?
        ORDER BY (u.kind = 'function') DESC, uv.end_line - uv.start_line LIMIT 1
        """,
        (snap, path, line, line),
    ).fetchone()
    return row[0] if row else None


def _append_dossiers(cfg: Config, project: Project, run: sqlite3.Row, notes, report) -> None:
    for note in notes:
        project.area_named(note.area)  # validated before any write, see record()
        path = cfg.dossier_path(project.name, note.area)
        path.parent.mkdir(parents=True, exist_ok=True)
        header = "" if path.exists() else f"# {project.name} / {note.area} — dossier\n"
        with path.open("a") as f:
            f.write(f"{header}\n## run {run['id']} ({run['kind']}, {now()[:10]})\n\n")
            f.write(note.text.rstrip() + "\n")
        report.dossiers.append(note.area)


def _event(conn, finding_id, run_id, from_status, to_status, note=None) -> None:
    conn.execute(
        "INSERT INTO finding_events (finding_id, run_id, at, from_status, to_status, note) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (finding_id, run_id, now(), from_status, to_status, note),
    )


def record(conn: sqlite3.Connection, cfg: Config, run_id: int, data: dict) -> RecordReport:
    """Validate a subagent's result and apply it to the ledger atomically."""
    run = get_run(conn, run_id)
    if run["status"] != "started":
        raise LedgerError(f"run {run_id} is {run['status']}, not started")
    project = cfg.project(run["project"])
    schema = VerifyResult if run["kind"] == "verify" else AuditResult
    try:
        result = schema.model_validate(data)
    except ValidationError as e:
        raise LedgerError(f"result does not match the {schema.__name__} schema:\n{e}") from None
    if result.run_id != run_id:
        raise LedgerError(f"result is for run {result.run_id}, not {run_id}")
    try:
        for note in result.dossier:
            project.area_named(note.area)
    except ConfigError as e:
        raise LedgerError(str(e)) from None
    refs = {r["path"]: r for r in _snapshot_references(conn, cfg, run)}
    for un in result.upstream_notes:
        if un.component not in refs:
            known = ", ".join(sorted(refs)) or "none"
            raise LedgerError(f"upstream note component {un.component!r} is not a reference "
                              f"tree of this snapshot (known: {known})")

    report = RecordReport(run_id, run["kind"])
    with conn:
        if isinstance(result, AuditResult):
            _record_audit(conn, run, result, report)
        else:
            _record_verify(conn, run, result, report)
        for un in result.upstream_notes:
            ref = refs[un.component]
            conn.execute(
                "INSERT INTO upstream_notes (project, run_id, component, component_url, "
                "component_sha, title, description, locations, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (project.name, run_id, un.component, ref.get("url"), ref.get("sha"), un.title,
                 un.description, json.dumps([loc.model_dump() for loc in un.locations]), now()),
            )
            report.upstream.append(un.title)
        # Provenance: the agent definition in effect when the result came back.
        inputs = json.loads(run["inputs"] or "{}")
        agent = cfg.agent_path(agent_for(run["kind"]))
        if agent.is_file():
            inputs["agent"] = file_hash(agent)
        conn.execute(
            "UPDATE runs SET status = 'recorded', model = ?, summary = ?, finished_at = ?, "
            "inputs = ? WHERE id = ?",
            (result.model, getattr(result, "summary", None) or getattr(result, "reasoning", ""),
             now(), json.dumps(inputs), run_id),
        )
    # Files after the DB commit: a failure here leaves the ledger consistent.
    _append_dossiers(cfg, project, run, result.dossier, report)
    out = cfg.run_record_path(project.name, run_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n")
    brief_path(cfg, run_id).unlink(missing_ok=True)
    return report


def _record_audit(conn, run, result: AuditResult, report: RecordReport) -> None:
    snap = run["snapshot_id"]
    versions = {
        r["key"]: r
        for r in conn.execute(
            "SELECT u.id, u.key, u.kind, uv.content_hash FROM unit_versions uv "
            "JOIN units u ON u.id = uv.unit_id WHERE uv.snapshot_id = ?",
            (snap,),
        )
    }
    targets = {
        r["key"]
        for r in conn.execute(
            "SELECT u.key FROM run_targets t JOIN units u ON u.id = t.unit_id WHERE t.run_id = ?",
            (run["id"],),
        )
    }
    reported = {}
    # A sweep may report a whole file by its file-unit key: that covers the
    # file's function targets, and explicit function entries override it.
    if run["kind"] == "sweep":
        for us in result.units:
            if us.key in versions and versions[us.key]["kind"] == "file":
                prefix = us.key + "::"
                for key in targets:
                    if key.startswith(prefix):
                        reported[key] = us.model_copy(update={"key": key})
    for us in result.units:
        if us.key not in versions:
            raise LedgerError(f"unknown unit key {us.key!r} for this snapshot")
        if versions[us.key]["kind"] == "file":
            if run["kind"] != "sweep":
                raise LedgerError(f"{us.key!r} is a file; dive results list functions")
            continue
        if run["kind"] == "dive" and us.key not in targets:
            raise LedgerError(f"unit {us.key!r} is not a target of dive run {run['id']}")
        reported[us.key] = us
    for key, us in reported.items():
        v = versions[key]
        conn.execute(
            "INSERT INTO coverage (unit_id, content_hash, lens_id, run_id, status, note) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (v["id"], v["content_hash"], run["lens_id"], run["id"], us.status, us.note or None),
        )
        if us.status == "partial":
            report.partial += 1
        else:
            report.covered += 1
    report.missing = sorted(targets - reported.keys())

    for h in result.hypotheses:
        units_hit = [_unit_at(conn, snap, loc.path, loc.start_line) for loc in h.locations]
        if not any(units_hit):
            raise LedgerError(
                f"hypothesis {h.title!r} has no location in indexed {run['project']} code; "
                "a defect inside an external component belongs in upstream_notes"
            )
        slug = _unique_slug(conn, _slugify(h.slug or h.title))
        ts = now()
        fid = conn.execute(
            "INSERT INTO findings (project, slug, title, status, claim, auditor_notes, "
            "confidence, property, attacker, cwe, snapshot_id, origin_run_id, created_at, "
            "updated_at) VALUES (?, ?, ?, 'hypothesis', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "RETURNING id",
            (run["project"], slug, h.title, h.claim, h.auditor_notes, h.confidence,
             h.property, h.attacker, h.cwe, snap, run["id"], ts, ts),
        ).fetchone()[0]
        for loc, unit_id in zip(h.locations, units_hit, strict=True):
            conn.execute(
                "INSERT INTO finding_locations VALUES (?, ?, ?, ?, ?, ?)",
                (fid, loc.path, loc.start_line, loc.end_line, loc.symbol, unit_id),
            )
        _event(conn, fid, run["id"], None, "hypothesis", f"raised by {run['kind']} run")
        report.findings.append(slug)


def _record_verify(conn, run, result: VerifyResult, report: RecordReport) -> None:
    f = conn.execute(
        "SELECT f.* FROM run_targets t JOIN findings f ON f.id = t.finding_id WHERE t.run_id = ?",
        (run["id"],),
    ).fetchone()
    if f is None:
        raise LedgerError(f"verify run {run['id']} has no target finding")
    new = "hypothesis" if result.verdict == "inconclusive" else result.verdict
    if new not in TRANSITIONS[f["status"]]:
        raise LedgerError(f"finding {f['slug']} is {f['status']}; cannot become {new}")
    conn.execute(
        "UPDATE findings SET status = ?, title = coalesce(?, title), claim = coalesce(?, claim), "
        "property = coalesce(?, property), attacker = coalesce(?, attacker), "
        "cwe = coalesce(?, cwe), severity = coalesce(?, severity), "
        "duplicate_of = coalesce(?, duplicate_of), updated_at = ? WHERE id = ?",
        (new, result.revised_title, result.revised_claim, result.property, result.attacker,
         result.cwe, result.severity, result.duplicate_of, now(), f["id"]),
    )
    _event(conn, f["id"], run["id"], f["status"], new, f"verify: {result.verdict}")
    report.verdict = result.verdict
    report.findings.append(f["slug"])


def set_finding_status(
    conn: sqlite3.Connection, slug: str, status: str, note: str | None = None,
    duplicate_of: str | None = None,
) -> tuple[str, str]:
    """Move a finding through its lifecycle. Marking a duplicate by hand
    names the finding it duplicates (an existing, non-duplicate one), and
    takes the finding out of any cluster."""
    f = conn.execute("SELECT id, status FROM findings WHERE slug = ?", (slug,)).fetchone()
    if f is None:
        raise LedgerError(f"no finding {slug!r}")
    if status not in TRANSITIONS:
        raise LedgerError(f"unknown status {status!r}")
    if status not in TRANSITIONS[f["status"]]:
        raise LedgerError(f"{slug} is {f['status']}; allowed: {sorted(TRANSITIONS[f['status']])}")
    if (status == "duplicate") != (duplicate_of is not None):
        raise LedgerError("--of names the original exactly when marking a duplicate")
    if duplicate_of is not None:
        orig = conn.execute("SELECT status FROM findings WHERE slug = ?",
                            (duplicate_of,)).fetchone()
        if orig is None or duplicate_of == slug:
            raise LedgerError(f"no other finding {duplicate_of!r}")
        if orig["status"] == "duplicate":
            raise LedgerError(f"{duplicate_of} is itself a duplicate; name its original")
    with conn:
        conn.execute(
            "UPDATE findings SET status = ?, duplicate_of = coalesce(?, duplicate_of), "
            "cluster_id = CASE WHEN ? = 'duplicate' THEN NULL ELSE cluster_id END, "
            "updated_at = ? WHERE id = ?", (status, duplicate_of, status, now(), f["id"])
        )
        _event(conn, f["id"], None, f["status"], status,
               note if duplicate_of is None else f"duplicate of {duplicate_of}"
               + (f": {note}" if note else ""))
    return f["status"], status


# --- reports ---------------------------------------------------------------


def coverage_by_area(
    conn: sqlite3.Connection, snap: int, lens_ids: list[int] | None
) -> list[dict]:
    """Per area: function count, and how many are covered by a sweep / a dive
    at their current content hash (under any of `lens_ids`, or any lens)."""
    lens_filter = ""
    params: list = [snap]
    if lens_ids is not None:
        lens_filter = f"AND c.lens_id IN ({','.join('?' * len(lens_ids))})" if lens_ids else "AND 0"
    def covered(kind: str) -> str:
        return f"""EXISTS (SELECT 1 FROM coverage c JOIN runs r ON r.id = c.run_id
                   WHERE c.unit_id = uv.unit_id AND c.content_hash = uv.content_hash
                   AND r.kind = '{kind}' AND c.status IN ('clean', 'hypotheses') {lens_filter})"""
    sql = f"""
        SELECT uv.area, max(uv.priority) AS priority, count(*) AS functions,
               sum(uv.end_line - uv.start_line + 1) AS lines,
               sum({covered('sweep')}) AS swept, sum({covered('dive')}) AS dived
        FROM unit_versions uv JOIN units u ON u.id = uv.unit_id
        WHERE uv.snapshot_id = ? AND u.kind = 'function'
        GROUP BY uv.area ORDER BY priority DESC, uv.area
    """
    if lens_ids:
        params = [*lens_ids, *lens_ids, snap]
    return [dict(r) for r in conn.execute(sql, params)]
