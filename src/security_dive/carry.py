"""Carry findings from one ledger into another at a newer snapshot.

The use: a benchmark round at an old commit verified findings that may still
be live. Rather than waiting for dives on `main` to find them again, each is
copied into the target ledger as a hypothesis at the target snapshot, so the
ordinary blind verify loop re-checks it against current code.

Line numbers are remapped by diffing the file between the two snapshots (when
both trees are on disk), otherwise by offset into the same function. Each
location is classed by comparing its function's content hash: "unchanged",
"changed", "approx" (no function matched; only the file) or "gone". The
verifier sees none of this, nor the earlier verdict: only the claim (with a
note that its line numbers refer to the old commit) and the remapped
locations. Provenance goes in `carried_from` and a finding event.
"""

from __future__ import annotations

import difflib
import sqlite3
from collections.abc import Callable
from pathlib import Path

from .ledger import LedgerError, _event, _unique_slug, _unit_at, now

LineMap = Callable[[int], int]

DEFAULT_STATUSES = ("verified",)


def _src_unit(conn: sqlite3.Connection, snap: int, unit_id: int | None) -> sqlite3.Row | None:
    if unit_id is None:
        return None
    return conn.execute(
        "SELECT u.key, u.kind, u.path, u.symbol, uv.start_line, uv.end_line, uv.content_hash "
        "FROM units u JOIN unit_versions uv ON uv.unit_id = u.id AND uv.snapshot_id = ? "
        "WHERE u.id = ?", (snap, unit_id)).fetchone()


def _dst_unit(conn: sqlite3.Connection, project: str, snap: int, src: sqlite3.Row,
              hint: int | None = None) -> sqlite3.Row | None:
    """The target unit for source unit `src`: same key, unless `hint` (the
    diff-mapped line) lies in a different same-named variant — #if variant
    ordinals (@n) shift when a branch is added before them."""
    cols = ("SELECT u.id, u.key, u.kind, uv.start_line, uv.end_line, uv.content_hash "
            "FROM units u JOIN unit_versions uv ON uv.unit_id = u.id AND uv.snapshot_id = ? ")
    row = conn.execute(cols + "WHERE u.project = ? AND u.key = ?",
                       (snap, project, src["key"])).fetchone()
    if src["kind"] != "function":
        return row
    if row is not None and (hint is None or row["start_line"] <= hint <= row["end_line"]):
        return row
    variants = conn.execute(cols + "WHERE u.project = ? AND u.path = ? AND u.symbol = ? "
                            "AND u.kind = 'function'",
                            (snap, project, src["path"], src["symbol"])).fetchall()
    if hint is not None:
        for v in variants:
            if v["start_line"] <= hint <= v["end_line"]:
                return v
    if row is not None:
        return row
    near = hint if hint is not None else src["start_line"]
    return min(variants, key=lambda r: abs(r["start_line"] - near), default=None)


def _file_unit(conn: sqlite3.Connection, project: str, snap: int, path: str
               ) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT u.id, uv.end_line FROM units u JOIN unit_versions uv "
        "ON uv.unit_id = u.id AND uv.snapshot_id = ? "
        "WHERE u.project = ? AND u.path = ? AND u.kind = 'file'",
        (snap, project, path)).fetchone()


def line_map(old: list[str], new: list[str]) -> LineMap:
    """Map 1-based line numbers of `old` onto `new` by diff: equal lines map
    exactly; a line in a replaced block maps proportionally into the new block,
    a deleted line to where the block was."""
    ops = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    def f(line: int) -> int:
        i = line - 1
        for tag, i1, i2, j1, j2 in ops:
            if i1 <= i < i2:
                if tag == "equal":
                    return j1 + (i - i1) + 1
                return min(j1 + (i - i1), max(j2 - 1, j1)) + 1
        return len(new) or 1
    return f


def map_location(src_conn, src_snap: int, dst_conn, project: str, dst_snap: int,
                 loc: sqlite3.Row, lines: LineMap | None = None) -> dict:
    """Map one source finding location onto the target snapshot. `lines`, when
    given, maps line numbers of the location's file between the snapshots."""
    out = {"path": loc["path"], "start_line": loc["start_line"], "end_line": loc["end_line"],
           "symbol": loc["symbol"], "unit_id": None, "state": "gone"}
    src = _src_unit(src_conn, src_snap, loc["unit_id"])
    hint = lines(loc["start_line"]) if lines else None
    dst = _dst_unit(dst_conn, project, dst_snap, src, hint) if src is not None else None
    f = _file_unit(dst_conn, project, dst_snap, loc["path"])
    if f is None:
        return out
    if dst is not None and src["kind"] == "function":
        def shift(line):
            if line is None:
                return None
            moved = lines(line) if lines else line - src["start_line"] + dst["start_line"]
            return min(max(moved, dst["start_line"]), dst["end_line"])
        out.update(start_line=shift(loc["start_line"]), end_line=shift(loc["end_line"]),
                   unit_id=dst["id"],
                   state="unchanged" if dst["content_hash"] == src["content_hash"]
                   else "changed")
        return out
    end = f["end_line"]
    def clip(line):
        return None if line is None else min(lines(line) if lines else line, end)
    out.update(start_line=clip(loc["start_line"]), end_line=clip(loc["end_line"]))
    same = dst is not None and src is not None and dst["content_hash"] == src["content_hash"]
    if same:
        out.update(unit_id=dst["id"], state="unchanged")
    else:
        # The function was renamed or removed: whatever now holds the line.
        out.update(unit_id=_unit_at(dst_conn, dst_snap, loc["path"], out["start_line"])
                   or f["id"], state="approx")
    return out


def _code_state(states: list[str]) -> str:
    if all(s == "gone" for s in states):
        return "gone"
    if all(s == "unchanged" for s in states if s != "gone"):
        return "unchanged"
    return "changed"


def carry(src_conn: sqlite3.Connection, src_ledger: str, dst_conn: sqlite3.Connection,
          project: str, dst_snap: int, statuses=DEFAULT_STATUSES,
          slugs: list[str] | None = None, dry_run: bool = False,
          tree_for: Callable[[str], Path] | None = None) -> list[dict]:
    """Copy matching source findings into the target ledger as hypotheses.

    Returns one row per source finding: what happened and why. Findings whose
    every location is gone are reported, not carried; ones carried before (by
    `carried_from`) are skipped. `tree_for(sha)` gives a snapshot directory,
    used to remap lines by diff; without it lines move by function offset.
    """
    maps: dict[tuple[str, str], LineMap | None] = {}
    def lines_for(src_sha: str, path: str) -> LineMap | None:
        if tree_for is None:
            return None
        if (src_sha, path) not in maps:
            a, b = tree_for(src_sha) / path, tree_for(dst_sha) / path
            maps[src_sha, path] = (line_map(a.read_text(errors="replace").splitlines(),
                                            b.read_text(errors="replace").splitlines())
                                   if a.is_file() and b.is_file() else None)
        return maps[src_sha, path]

    dst_sha = dst_conn.execute("SELECT sha FROM snapshots WHERE id = ?",
                               (dst_snap,)).fetchone()["sha"]
    q = ("SELECT f.*, s.sha FROM findings f JOIN snapshots s ON s.id = f.snapshot_id "
         f"WHERE f.project = ? AND f.status IN ({','.join('?' * len(statuses))})")
    params: list = [project, *statuses]
    if slugs:
        q += f" AND f.slug IN ({','.join('?' * len(slugs))})"
        params += slugs
    findings = src_conn.execute(q + " ORDER BY f.id", params).fetchall()
    if slugs and (missing := set(slugs) - {f["slug"] for f in findings}):
        raise LedgerError(f"not in ledger {src_ledger} with status {'/'.join(statuses)}: "
                          + ", ".join(sorted(missing)))
    rows = []
    for f in findings:
        origin = f"{src_ledger}:{f['slug']}"
        locs = [map_location(src_conn, f["snapshot_id"], dst_conn, project, dst_snap, loc,
                             lines_for(f["sha"], loc["path"]))
                for loc in src_conn.execute(
                    "SELECT * FROM finding_locations WHERE finding_id = ? ORDER BY rowid",
                    (f["id"],))]
        states = [loc["state"] for loc in locs]
        row = {"source": f["slug"], "status": f["status"], "from_sha": f["sha"],
               "code": _code_state(states), "locations": locs, "slug": None, "skipped": None}
        rows.append(row)
        prior = dst_conn.execute("SELECT slug FROM findings WHERE carried_from = ?",
                                 (origin,)).fetchone()
        if prior:
            row["skipped"] = f"already carried as {prior['slug']}"
            continue
        kept = [loc for loc in locs if loc["state"] != "gone"]
        if not any(loc["unit_id"] for loc in kept):
            row["skipped"] = "no location maps to the target snapshot"
            continue
        if dry_run:
            continue
        claim = f["claim"]
        if f["sha"] != dst_sha:
            claim = (f"[Line numbers in this claim refer to {project}@{f['sha'][:12]}; the "
                     f"locations have been mapped to this snapshot.]\n\n{claim}")
        with dst_conn:
            slug = _unique_slug(dst_conn, f["slug"])
            ts = now()
            fid = dst_conn.execute(
                "INSERT INTO findings (project, slug, title, status, claim, auditor_notes, "
                "confidence, property, attacker, cwe, snapshot_id, origin_run_id, created_at, "
                "updated_at, carried_from) "
                "VALUES (?, ?, ?, 'hypothesis', ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?) RETURNING id",
                (project, slug, f["title"], claim, f["auditor_notes"], f["confidence"],
                 f["property"], f["attacker"], f["cwe"], dst_snap, ts, ts, origin),
            ).fetchone()[0]
            for loc in kept:
                dst_conn.execute(
                    "INSERT INTO finding_locations VALUES (?, ?, ?, ?, ?, ?)",
                    (fid, loc["path"], loc["start_line"], loc["end_line"], loc["symbol"],
                     loc["unit_id"]))
            _event(dst_conn, fid, None, None, "hypothesis",
                   f"carried from ledger {src_ledger} finding {f['slug']} "
                   f"({f['status']} at {f['sha'][:12]}); code {row['code']}")
        row["slug"] = slug
    return rows
