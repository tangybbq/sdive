"""Ranking: the order in which work is handed out.

Zephyr's attack surfaces alone are ~30x MCUboot's core, so the queue must put
the likeliest code first. A unit's **score** is its area priority plus:

- a bonus for **signals** in its text (deterministic, computed at indexing):
  packet and PDU accessors, copies, length arithmetic, syscall verification,
  assertion-only checks, reference counting, handler-like names;
- an adjustment for **builds** (`sdive build`), once any are recorded: `.c`
  code no recorded build compiles sinks (headers are not judged: compile
  databases list only translation units);
- an adjustment for **reach**, the cheap `sdive-ranker` agent's judgement of
  how directly an attacker reaches the function (`/sdive-rank`).

Queues order by score (then path and line), so area priority stays the main
key and the rest orders work within and across neighbouring bands.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from .config import Config, Project
from .schemas import RankResult


class RankError(Exception):
    pass

# name, pattern, weight per hit, cap on hits counted
SIGNALS: list[tuple[str, re.Pattern[str], float, int]] = [
    ("parse", re.compile(
        r"\b(?:net_buf_(?:simple_)?(?:pull|remove)\w*|net_pkt_(?:read|skip|get_data|cursor_)\w*"
        r"|NET_PKT_DATA_ACCESS\w*|sys_get_(?:le|be)\d+|zcbor_\w+_(?:decode|get)\w*"
        r"|json_\w*parse\w*|coap_\w+_(?:get|find)\w*|bt_\w+_pull\w*)\s*\("), 0.15, 6),
    ("copy", re.compile(
        r"\b(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|net_buf_(?:simple_)?add_mem"
        r"|net_pkt_write\w*|k_usermode_\w*copy)\s*\("), 0.1, 6),
    ("len_arith", re.compile(
        r"\b\w*(?:len|size|offset|off|count|cnt|remaining)\w*\s*-[^>=-]|-\s*sizeof\b"
        r"|\b\w*(?:len|size)\w*\s*\+=", re.IGNORECASE), 0.1, 6),
    ("syscall", re.compile(r"\b(?:K_SYSCALL_\w+|z_vrfy_\w+|k_usermode_\w+|K_OOPS)\b"), 0.25, 4),
    ("assert_check", re.compile(
        r"__ASSERT(?:_NO_MSG)?\s*\([^;]*\b\w*(?:len|size|idx|index|count)\w*", re.IGNORECASE),
     0.15, 3),
    ("lifetime", re.compile(
        r"\b(?:\w+_unref|\w+_ref|k_work_cancel\w*|k_free|k_heap_free|net_pkt_frag_unref"
        r"|k_object_free)\s*\("), 0.05, 6),
]
HANDLER_NAME = re.compile(
    r"(?:^|_)(?:recv|rx|input|handle|handler|parse|process|decode|req|rsp|ind|cb|"
    r"setup|vendor_request|class_request|event)(?:_|$)|^z_vrfy_", re.IGNORECASE)
MAX_SIGNAL_BONUS = 1.5
UNBUILT = -1.5
REACH_ADJ = {0: -2.0, 1: -0.5, 2: 0.5, 3: 1.5}


def signals(text: str, name: str | None) -> dict[str, int]:
    """Signal hit counts for one function's source text (comments included;
    cheap and good enough for ordering)."""
    out = {k: len(p.findall(text)) for k, p, _w, _cap in SIGNALS}
    out = {k: v for k, v in out.items() if v}
    if name and HANDLER_NAME.search(name):
        out["handler"] = 1
    return out


def signal_bonus(sig: dict[str, int]) -> float:
    weights = {k: (w, cap) for k, _p, w, cap in SIGNALS}
    total = sum(w * min(sig.get(k, 0), cap) for k, (w, cap) in weights.items())
    total += 0.2 * sig.get("handler", 0)
    return min(MAX_SIGNAL_BONUS, round(total, 3))


def score(priority: int, sig: dict[str, int], built: bool | None, reach: int | None) -> float:
    s = priority + signal_bonus(sig)
    if built is False:
        s += UNBUILT
    if reach is not None:
        s += REACH_ADJ[reach]
    return round(s, 3)


def carry_reach(conn: sqlite3.Connection, snap: int) -> int:
    """Copy into `snap` the latest reach judgement of each function whose
    content is unchanged from a snapshot where it was judged (or carried),
    unless `snap` already has one. Returns the number carried."""
    with conn:
        cur = conn.execute(
            """INSERT INTO unit_reach (snapshot_id, unit_id, reach, attacker, reason, model,
                                       created_at, carried_from)
               SELECT uv.snapshot_id, r.unit_id, r.reach, r.attacker, r.reason, r.model,
                      r.created_at, coalesce(r.carried_from, r.snapshot_id)
               FROM unit_versions uv JOIN unit_reach r ON r.id = (
                   SELECT max(r2.id) FROM unit_reach r2
                   JOIN unit_versions o ON o.snapshot_id = r2.snapshot_id
                                       AND o.unit_id = r2.unit_id
                   WHERE r2.unit_id = uv.unit_id AND r2.snapshot_id != uv.snapshot_id
                     AND o.content_hash = uv.content_hash)
               WHERE uv.snapshot_id = ?
                 AND NOT EXISTS (SELECT 1 FROM unit_reach x
                                 WHERE x.snapshot_id = uv.snapshot_id
                                   AND x.unit_id = uv.unit_id)""", (snap,))
    return cur.rowcount


def rescore(conn: sqlite3.Connection, snap: int) -> int:
    """Recompute every unit's score in `snap` from its priority, signals,
    the snapshot's recorded builds (if any) and recorded reach. Returns the
    number of units scored."""
    have_builds = conn.execute(
        "SELECT 1 FROM builds WHERE snapshot_id = ? AND status = 'ok' LIMIT 1",
        (snap,)).fetchone() is not None
    built_paths = {r[0] for r in conn.execute(
        "SELECT DISTINCT path FROM file_builds WHERE snapshot_id = ?", (snap,))}
    reach = {r["unit_id"]: r["reach"] for r in conn.execute(
        """SELECT unit_id, reach FROM unit_reach WHERE snapshot_id = ?
           AND id IN (SELECT max(id) FROM unit_reach WHERE snapshot_id = ? GROUP BY unit_id)""",
        (snap, snap))}
    rows = conn.execute(
        """SELECT uv.unit_id, uv.priority, uv.signals, u.path FROM unit_versions uv
           JOIN units u ON u.id = uv.unit_id WHERE uv.snapshot_id = ?""", (snap,)).fetchall()
    with conn:
        conn.executemany(
            "UPDATE unit_versions SET score = ? WHERE snapshot_id = ? AND unit_id = ?",
            [(score(r["priority"], json.loads(r["signals"] or "{}"),
                    (r["path"] in built_paths) if have_builds and r["path"].endswith(".c")
                    else None,
                    reach.get(r["unit_id"])), snap, r["unit_id"]) for r in rows])
    return len(rows)


# --- the ranker agent ------------------------------------------------------
#
# `/sdive-rank` hands batches of the top-scored files whose functions have no
# reach judgement yet to the cheap `sdive-ranker` subagent. Rank briefs are
# not ledger runs (no coverage, no findings): a brief in staging leases its
# units until it is recorded or deleted.

RANK_MAX_FUNCTIONS = 80

# A brief's context budget. Haiku is much cheaper while a request stays under
# 100K tokens of context, so briefs are sized to keep the ranker's last turn
# below that with room for its searches. The estimate was fitted on measured
# ranker transcripts: a fixed part (agent prompt, brief envelope, threat
# model), a per-function part (its brief entry and its result entry), and the
# source read with line numbers.
RANK_MAX_TOKENS = 80_000
RANK_BASE_TOKENS = 18_000
RANK_TOKENS_PER_FUNCTION = 330
RANK_TOKENS_PER_BYTE = 0.8
RANK_HEAD_LINES = 100  # a split file's opening (includes, types) read for context


def estimate_tokens(functions: int, source_bytes: int) -> float:
    """Context one brief piece adds (without the fixed base)."""
    return RANK_TOKENS_PER_FUNCTION * functions + RANK_TOKENS_PER_BYTE * source_bytes


def file_sizer(root: Path):
    """`size(path, start=None, end=None)`: bytes of a snapshot file, or of a
    1-based inclusive line range in it (0 for a missing file)."""
    offsets: dict[str, list[int]] = {}

    def size(path: str, start: int | None = None, end: int | None = None) -> int:
        if path not in offsets:
            try:
                data = (root / path).read_bytes()
            except OSError:
                data = b""
            acc = [0]
            for line in data.splitlines(keepends=True):
                acc.append(acc[-1] + len(line))
            offsets[path] = acc
        acc = offsets[path]
        if start is None:
            return acc[-1]
        lo = min(max(start - 1, 0), len(acc) - 1)
        hi = min(max(end or start, lo), len(acc) - 1)
        return acc[hi] - acc[lo]
    return size


def _pieces(path: str, fns: list, size, max_tokens: float):
    """A file's functions as brief pieces (path, rows, lines): the whole file
    (lines None) when it fits the budget, else consecutive line-range chunks
    that each fit (a single over-large function still gets a chunk)."""
    budget = max_tokens - RANK_BASE_TOKENS
    if size is None or estimate_tokens(len(fns), size(path)) <= budget:
        yield path, fns, None
        return
    head = size(path, 1, RANK_HEAD_LINES)
    chunk: list = []
    for r in sorted(fns, key=lambda r: r["start_line"]):
        trial = chunk + [r]
        cost = estimate_tokens(len(trial), head + size(path, trial[0]["start_line"],
                                                       r["end_line"]))
        if chunk and cost > budget:
            yield path, chunk, [chunk[0]["start_line"], chunk[-1]["end_line"]]
            chunk = [r]
        else:
            chunk = trial
    if chunk:
        yield path, chunk, [chunk[0]["start_line"], chunk[-1]["end_line"]]


def _piece_cost(piece, size) -> float:
    path, fns, lines = piece
    if size is None:
        return 0.0
    src = size(path) if lines is None else size(path, 1, RANK_HEAD_LINES) + size(path, *lines)
    return estimate_tokens(len(fns), src)


def _outstanding(cfg: Config) -> set[str]:
    keys: set[str] = set()
    for f in cfg.staging.glob("rank-*.brief.json"):
        try:
            b = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        keys.update(fn["key"] for file in b.get("files", []) for fn in file["functions"])
    return keys


def unranked(conn: sqlite3.Connection, snap: int, min_priority: int = 0,
             area: str | None = None) -> list[sqlite3.Row]:
    """Function units in `snap` (in `area`, if given) with no reach
    judgement, best score first."""
    return conn.execute(
        """SELECT u.id, u.key, u.path, u.symbol, uv.area, uv.priority, uv.score,
                  uv.start_line, uv.end_line, uv.signals
           FROM unit_versions uv JOIN units u ON u.id = uv.unit_id
           WHERE uv.snapshot_id = :snap AND u.kind = 'function' AND uv.priority >= :min
             AND (:area IS NULL OR uv.area = :area)
             AND NOT EXISTS (SELECT 1 FROM unit_reach r
                             WHERE r.snapshot_id = uv.snapshot_id AND r.unit_id = uv.unit_id)
           ORDER BY uv.score DESC, u.path, uv.start_line""",
        {"snap": snap, "min": min_priority, "area": area}).fetchall()


def batches(rows: list[sqlite3.Row], max_functions: int = RANK_MAX_FUNCTIONS,
            size=None, max_tokens: float = RANK_MAX_TOKENS):
    """Group unranked function rows (best first) into briefs, in order of each
    file's best function. Yields lists of (path, rows, lines) pieces: whole
    files (lines None) packed up to `max_functions` and, when `size` (from
    `file_sizer`) is given, the `max_tokens` context budget; a file too large
    for the budget is split into line-range chunks, one brief each."""
    files: dict[str, list] = {}
    for r in rows:
        files.setdefault(r["path"], []).append(r)
    batch: list = []
    n = 0
    cost = float(RANK_BASE_TOKENS)
    for path, fns in files.items():
        for piece in _pieces(path, fns, size, max_tokens):
            pc = _piece_cost(piece, size)
            k = len(piece[1])
            if batch and (n + k > max_functions or piece[2] is not None
                          or batch[-1][2] is not None or cost + pc > max_tokens):
                yield batch
                batch, n, cost = [], 0, float(RANK_BASE_TOKENS)
            batch.append(piece)
            n += k
            cost += pc
    if batch:
        yield batch


def write_brief(conn: sqlite3.Connection, cfg: Config, project: Project, snap: int,
                max_functions: int = RANK_MAX_FUNCTIONS, min_priority: int = 0,
                max_tokens: float = RANK_MAX_TOKENS, area: str | None = None) -> dict | None:
    """A rank brief for the best unranked files (by their best function's
    score, within `max_functions` and the `max_tokens` context budget; a file
    too large for the budget comes as a line range), or None when nothing is
    left. `area` limits it to that area's functions."""
    leased = _outstanding(cfg)
    rows = [r for r in unranked(conn, snap, min_priority, area) if r["key"] not in leased]
    if not rows:
        return None
    sha = conn.execute("SELECT sha FROM snapshots WHERE id = ?", (snap,)).fetchone()[0]
    size = file_sizer(cfg.snapshot_path(project.name, sha))
    batch = [{"path": path, "area": fns[0]["area"],
              **({"lines": lines} if lines else {}),
              "functions": [
                  {"key": r["key"], "symbol": r["symbol"], "start_line": r["start_line"],
                   "end_line": r["end_line"], "signals": json.loads(r["signals"] or "{}")}
                  for r in sorted(fns, key=lambda r: r["start_line"])]}
             for path, fns, lines in next(batches(rows, max_functions, size, max_tokens))]
    brief_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    staging = cfg.staging
    staging.mkdir(parents=True, exist_ok=True)
    b = {
        "brief_id": brief_id,
        "kind": "rank",
        "project": project.name,
        "snapshot": {"sha": sha, "path": str(cfg.snapshot_path(project.name, sha))},
        "threat_model": str(project.threat_model) if project.threat_model else None,
        "agent": "sdive-ranker",
        "brief_path": str(staging / f"rank-{brief_id}.brief.json"),
        "result_path": str(staging / f"rank-{brief_id}.json"),
        "result_schema": "rank",
        "record_command": f"uv run sdive --ledger {cfg.ledger} rank record {brief_id}",
        "files": batch,
    }
    Path(b["brief_path"]).write_text(json.dumps(b, indent=2) + "\n")
    return b


REASON_MAX = 200


def _shorten_reasons(data: object) -> int:
    """Cut over-long reasons to REASON_MAX in place (Haiku miscounts
    characters; a reason is a one-line note). Returns how many were cut."""
    n = 0
    units = data.get("units") if isinstance(data, dict) else None
    for u in units if isinstance(units, list) else []:
        r = u.get("reason") if isinstance(u, dict) else None
        if isinstance(r, str) and len(r) > REASON_MAX:
            u["reason"] = r[:REASON_MAX - 1].rstrip() + "…"
            n += 1
    return n


def record(conn: sqlite3.Connection, cfg: Config, brief_id: str,
           result_path: Path | None = None) -> tuple[int, int]:
    """Validate a ranker result against its brief, store the judgements,
    rescore the snapshot. Returns the number of units judged and the number
    of over-long reasons shortened."""
    bpath = cfg.staging / f"rank-{brief_id}.brief.json"
    if not bpath.is_file():
        raise RankError(f"no rank brief {brief_id} in {cfg.staging}")
    b = json.loads(bpath.read_text())
    rpath = result_path or Path(b["result_path"])
    if not rpath.is_file():
        raise RankError(f"no result file {rpath}")
    try:
        data = json.loads(rpath.read_text())
    except json.JSONDecodeError as e:
        raise RankError(f"result is not valid JSON: {e}") from None
    shortened = _shorten_reasons(data)
    try:
        result = RankResult.model_validate(data)
    except ValidationError as e:
        raise RankError(f"result does not match the RankResult schema:\n{e}") from None
    if result.brief_id != brief_id:
        raise RankError(f"result is for brief {result.brief_id}, not {brief_id}")
    wanted = {fn["key"] for f in b["files"] for fn in f["functions"]}
    got = {u.key for u in result.units}
    if got - wanted:
        raise RankError(f"units not in the brief: {sorted(got - wanted)[:5]}")
    if wanted - got:
        raise RankError(f"{len(wanted - got)} brief units have no judgement, e.g. "
                        f"{sorted(wanted - got)[:5]}")
    snap = conn.execute(
        "SELECT id FROM snapshots WHERE project = ? AND sha = ?",
        (b["project"], b["snapshot"]["sha"])).fetchone()[0]
    ids = {r["key"]: r["id"] for r in conn.execute(
        "SELECT id, key FROM units WHERE project = ?", (b["project"],))}
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    created = datetime.strptime(brief_id, "%Y%m%dT%H%M%S%f").replace(tzinfo=UTC)
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO rank_briefs (brief_id, project, snapshot_id, functions, "
            "created_at, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (brief_id, b["project"], snap, len(wanted), created.isoformat(),
             datetime.now(UTC).isoformat()))
        conn.executemany(
            "INSERT INTO unit_reach (snapshot_id, unit_id, reach, attacker, reason, model, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(snap, ids[u.key], u.reach, u.attacker, u.reason, result.model, ts)
             for u in result.units])
    rescore(conn, snap)
    out = cfg.ledger_dir / "rank" / b["project"] / f"rank-{brief_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rpath.read_text())
    bpath.unlink()
    rpath.unlink(missing_ok=True)
    return len(result.units), shortened
