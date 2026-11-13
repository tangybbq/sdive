"""Triage after verification: clusters, and release scoping.

A **cluster** groups verified findings that one fix closes. It is the unit of
an upstream fix PR and of an advisory (decided 2026-11-13: one advisory per
cluster). Its **track** says where it goes: `advisory` (the code shipped in a
release: GHSA, CVE, then the fix) or `plain-fix` (merged since the last release
and never shipped: an ordinary fix, no advisory). The track is a recorded
human decision, never derived.

**Release scoping** is the evidence for that decision. Each location of a
finding is blamed at the finding's snapshot (`-w -M -C`, so whitespace changes
and moved or copied code keep their original commit), and each blamed commit is
mapped to the first release tag containing it. A finding is `released` when
every flagged line, as it reads now, already existed in the latest release
before the snapshot; `post-release` when none did; `mixed` otherwise (a line
was touched since; read it to decide whether the bug predates the change);
`unknown` when nothing could be blamed (e.g. a path inside a submodule).
`as_is_since` is the first release holding all the released lines in their
present form: an upper bound on when the bug arrived (it may be older; the
advisory's real floor is settled later, from the code).

Release tags are exactly `vX.Y.Z`, as in zepsec: `-rc` and vendor tags never
count.
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .ledger import LedgerError, now

RELEASE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


# --- clusters --------------------------------------------------------------


def _cluster(conn: sqlite3.Connection, slug: str) -> sqlite3.Row:
    c = conn.execute("SELECT * FROM clusters WHERE slug = ?", (slug,)).fetchone()
    if c is None:
        raise LedgerError(f"no cluster {slug!r}")
    return c


def _members_ok(conn: sqlite3.Connection, project: str, slugs: list[str], cluster_id: int | None,
                move: bool) -> list[sqlite3.Row]:
    rows = []
    for s in slugs:
        f = conn.execute("SELECT f.*, c.slug AS cluster FROM findings f "
                         "LEFT JOIN clusters c ON c.id = f.cluster_id WHERE f.slug = ?",
                         (s,)).fetchone()
        if f is None or f["project"] != project:
            raise LedgerError(f"no {project} finding {s!r}")
        if f["status"] not in ("verified", "exported", "fixed"):
            raise LedgerError(f"{s} is {f['status']}; only verified findings join clusters")
        if f["cluster_id"] not in (None, cluster_id) and not move:
            raise LedgerError(f"{s} is already in cluster {f['cluster']} (use --move)")
        rows.append(f)
    return rows


def new_cluster(conn: sqlite3.Connection, project: str, slug: str, title: str,
                rationale: str | None, findings: list[str], move: bool = False) -> int:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", slug):
        raise LedgerError(f"cluster slug {slug!r}: lowercase letters, digits and '-'")
    if conn.execute("SELECT 1 FROM clusters WHERE slug = ?", (slug,)).fetchone():
        raise LedgerError(f"cluster {slug!r} exists")
    _members_ok(conn, project, findings, None, move)
    with conn:
        cur = conn.execute(
            "INSERT INTO clusters (project, slug, title, rationale, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)", (project, slug, title, rationale, now(), now()))
        _assign(conn, cur.lastrowid, findings)
    return cur.lastrowid


def _assign(conn: sqlite3.Connection, cluster_id: int | None, findings: list[str]) -> None:
    for s in findings:
        conn.execute("UPDATE findings SET cluster_id = ?, updated_at = ? WHERE slug = ?",
                     (cluster_id, now(), s))


def add_to_cluster(conn: sqlite3.Connection, slug: str, findings: list[str],
                   move: bool = False) -> None:
    c = _cluster(conn, slug)
    _members_ok(conn, c["project"], findings, c["id"], move)
    with conn:
        _assign(conn, c["id"], findings)
        conn.execute("UPDATE clusters SET updated_at = ? WHERE id = ?", (now(), c["id"]))


def remove_from_cluster(conn: sqlite3.Connection, slug: str, findings: list[str]) -> None:
    c = _cluster(conn, slug)
    for s in findings:
        f = conn.execute("SELECT cluster_id FROM findings WHERE slug = ?", (s,)).fetchone()
        if f is None or f["cluster_id"] != c["id"]:
            raise LedgerError(f"{s} is not in cluster {slug}")
    with conn:
        _assign(conn, None, findings)


def set_track(conn: sqlite3.Connection, slug: str, track: str, note: str) -> None:
    c = _cluster(conn, slug)
    if track not in ("advisory", "plain-fix"):
        raise LedgerError(f"unknown track {track!r}")
    if not note.strip():
        raise LedgerError("a track decision needs a note saying why")
    with conn:
        conn.execute("UPDATE clusters SET track = ?, track_note = ?, updated_at = ? WHERE id = ?",
                     (track, note, now(), c["id"]))


def cluster_members(conn: sqlite3.Connection, cluster_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT f.*, s.verdict AS scope, s.as_is_since, s.latest_release FROM findings f "
        "LEFT JOIN finding_scope s ON s.finding_id = f.id AND s.snapshot_id = f.snapshot_id "
        "WHERE f.cluster_id = ? ORDER BY f.id", (cluster_id,)).fetchall()


def combine(verdicts: list[str | None]) -> str | None:
    """A cluster's scope from its members': unanimous, else mixed."""
    known = {v for v in verdicts if v and v != "unknown"}
    if not verdicts or any(v is None for v in verdicts):
        return None   # some member not scoped yet
    if not known:
        return "unknown"
    return known.pop() if len(known) == 1 else "mixed"


def cluster_report(conn: sqlite3.Connection, slug: str) -> dict:
    c = _cluster(conn, slug)
    members = cluster_members(conn, c["id"])
    return {
        **dict(c),
        "scope": combine([m["scope"] for m in members]),
        "members": [{k: m[k] for k in ("slug", "status", "title", "property", "attacker", "cwe",
                                       "severity", "confidence", "scope", "as_is_since")}
                    for m in members],
    }


def unclustered(conn: sqlite3.Connection, project: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM findings WHERE project = ? AND status IN ('verified', 'exported') "
        "AND cluster_id IS NULL ORDER BY id", (project,)).fetchall()


# --- release scoping -------------------------------------------------------


def _git(git_dir: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(git_dir), *args], capture_output=True, text=True)


def _version(tag: str) -> tuple[int, int, int]:
    m = RELEASE_TAG.match(tag)
    assert m, tag
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


class Releases:
    """Release tags of a mirror, with a per-commit first-release cache."""

    def __init__(self, git_dir: Path) -> None:
        self.git_dir = git_dir
        out = _git(git_dir, "tag", "--list", "v*").stdout.split()
        self.tags = sorted((t for t in out if RELEASE_TAG.match(t)), key=_version)
        self._first: dict[str, str | None] = {}

    def latest_before(self, sha: str) -> str | None:
        for tag in reversed(self.tags):
            if _git(self.git_dir, "merge-base", "--is-ancestor", tag, sha).returncode == 0:
                return tag
        return None

    def first_containing(self, commit: str) -> str | None:
        if commit not in self._first:
            out = _git(self.git_dir, "tag", "--contains", commit, "--list", "v*").stdout.split()
            rel = sorted((t for t in out if RELEASE_TAG.match(t)), key=_version)
            self._first[commit] = rel[0] if rel else None
        return self._first[commit]


@dataclass
class Blamed:
    commit: str
    date: str
    summary: str
    lines: int


def blame(git_dir: Path, sha: str, path: str, start: int, end: int) -> list[Blamed]:
    """Commits owning lines start..end of path at sha (porcelain, -w -M -C)."""
    proc = _git(git_dir, "blame", "--porcelain", "-w", "-M", "-C", "-L", f"{start},{end}",
                sha, "--", path)
    if proc.returncode != 0:
        raise LedgerError(proc.stderr.strip() or f"git blame {path} failed")
    meta: dict[str, dict] = {}
    counts: dict[str, int] = defaultdict(int)
    current = None
    for line in proc.stdout.splitlines():
        if line.startswith("\t"):
            counts[current] += 1
            continue
        parts = line.split(" ")
        if len(parts) >= 3 and re.fullmatch(r"[0-9a-f]{40}", parts[0]):
            current = parts[0]
            meta.setdefault(current, {})
        elif current and parts[0] in ("committer-time", "summary"):
            meta[current][parts[0]] = line.split(" ", 1)[1]
    out = []
    for c, n in counts.items():
        ts = meta[c].get("committer-time")
        date = datetime.fromtimestamp(int(ts), UTC).strftime("%Y-%m-%d") if ts else ""
        out.append(Blamed(c, date, meta[c].get("summary", ""), n))
    return sorted(out, key=lambda b: b.date)


def scope_finding(conn: sqlite3.Connection, git_dir: Path, releases: Releases,
                  finding_id: int) -> dict:
    """Blame a finding's locations at its snapshot and store the verdict."""
    f = conn.execute("SELECT f.id, f.slug, f.snapshot_id, s.sha FROM findings f "
                     "JOIN snapshots s ON s.id = f.snapshot_id WHERE f.id = ?",
                     (finding_id,)).fetchone()
    if f is None:
        raise LedgerError(f"finding {finding_id} has no snapshot")
    latest = releases.latest_before(f["sha"])
    locs = conn.execute("SELECT path, start_line, end_line, symbol FROM finding_locations "
                        "WHERE finding_id = ? ORDER BY rowid", (finding_id,)).fetchall()
    detail, released, post, since = [], 0, 0, None
    for loc in locs:
        end = loc["end_line"] or loc["start_line"]
        entry = {"path": loc["path"], "lines": [loc["start_line"], end], "symbol": loc["symbol"]}
        try:
            blamed = blame(git_dir, f["sha"], loc["path"], loc["start_line"], end)
        except LedgerError as e:
            entry["error"] = str(e)
            detail.append(entry)
            continue
        entry["commits"] = []
        for b in blamed:
            rel = releases.first_containing(b.commit)
            shipped = rel is not None and latest is not None and _version(rel) <= _version(latest)
            if shipped:
                released += b.lines
                since = rel if since is None or _version(rel) > _version(since) else since
            else:
                post += b.lines
            entry["commits"].append({"sha": b.commit, "date": b.date, "summary": b.summary,
                                     "lines": b.lines, "first_release": rel,
                                     "post_release": not shipped})
        detail.append(entry)
    verdict = ("unknown" if released + post == 0 else
               "released" if post == 0 else "post-release" if released == 0 else "mixed")
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO finding_scope (finding_id, snapshot_id, latest_release, "
            "verdict, as_is_since, detail, scoped_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (finding_id, f["snapshot_id"], latest, verdict, since, json.dumps(detail), now()))
    return {"slug": f["slug"], "latest_release": latest, "verdict": verdict,
            "as_is_since": since, "released_lines": released, "post_release_lines": post,
            "locations": detail}


def scope_targets(conn: sqlite3.Connection, project: str, slugs: list[str],
                  redo: bool) -> list[int]:
    """Finding ids to scope: the named ones, else every verified/exported
    finding not yet scoped at its snapshot."""
    if slugs:
        ids = []
        for s in slugs:
            r = conn.execute("SELECT id FROM findings WHERE slug = ? AND project = ?",
                             (s, project)).fetchone()
            if r is None:
                raise LedgerError(f"no {project} finding {s!r}")
            ids.append(r["id"])
        return ids
    return [r["id"] for r in conn.execute(
        "SELECT f.id FROM findings f LEFT JOIN finding_scope s "
        "ON s.finding_id = f.id AND s.snapshot_id = f.snapshot_id "
        "WHERE f.project = ? AND f.status IN ('verified', 'exported') "
        "AND (? OR s.finding_id IS NULL) ORDER BY f.id", (project, redo))]
