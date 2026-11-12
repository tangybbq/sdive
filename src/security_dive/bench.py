"""Benchmark: score a ledger's findings against known ground truth.

Ground truth is imported from zepsec-style analysis directories (one directory
per item, with `disclosure.json` and/or `result.json`) into
`analysis/truth/<project>/<name>.json`. That directory must never be readable
by analysis agents (see .claude/settings.json); the report is for humans.

Matching is deliberately simple and shown, not hidden: a finding matches a
truth item at strength "unit" (a location in the same function as the item's
site), "near" (same file, within NEAR_LINES of the site), or "file" (same file
only). Only unit/near matches count as "raised"; a reviewer confirms them.
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .config import Config

NEAR_LINES = 40
VERDICTS = {"yes": "tp", "no": "fp", "unclear": "unclear"}
RAISED = ("unit", "near")
CONFIRMED = ("verified", "exported", "fixed")


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value.startswith("["):
        try:
            return [str(v) for v in ast.literal_eval(value)]
        except (ValueError, SyntaxError):
            return []
    return [value] if isinstance(value, str) and value else []


def _parse_site(site: str | None) -> dict | None:
    m = re.match(r"^\s*([^:\s]+):(\d+)", site or "")
    return {"path": m.group(1), "line": int(m.group(2))} if m else None


def import_items(corpus_dirs: list[Path]) -> list[dict]:
    """Truth items from zepsec-style corpora. Verdicts come from our own
    validation (`result.json` is_vulnerability), not the reporter's claim."""
    items = []
    for corpus in corpus_dirs:
        for d in sorted(p for p in corpus.iterdir() if p.is_dir()):
            disc, res = _load(d / "disclosure.json"), _load(d / "result.json")
            if not disc and not res:
                continue
            site = _parse_site(disc.get("site"))
            files = [site["path"]] if site else []
            files += [f for f in _as_list(res.get("affected_components")) if f not in files]
            items.append({
                "id": disc.get("short_id") or d.name,
                "slug": d.name,
                "title": disc.get("title") or res.get("advisory_summary") or d.name,
                "verdict": VERDICTS.get(str(res.get("is_vulnerability")).lower(), "unjudged"),
                "disposition": res.get("disposition"),
                "cwe": res.get("cwe") or disc.get("cwe"),
                "site": site,
                "files": files,
                "scanned_commit": disc.get("scanned_commit") or res.get("scanned_commit"),
                "origin": str(d),
            })
    return items


def truth_path(cfg: Config, project: str, name: str) -> Path:
    return cfg.truth_dir / project / f"{name}.json"


def save_truth(cfg: Config, project: str, name: str, corpus_dirs: list[Path]) -> dict:
    data = {
        "name": name,
        "project": project,
        "imported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sources": [str(c) for c in corpus_dirs],
        "items": import_items(corpus_dirs),
    }
    path = truth_path(cfg, project, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return data


def _resolve(path: str, known: set[str]) -> str | None:
    """Map a possibly partial path ("image_validate.c", "boot/x/.../y.c") onto
    one indexed path, if unambiguous."""
    if path in known:
        return path
    if "..." in path:
        rx = re.compile(re.escape(path).replace(re.escape("..."), ".*") + r"\Z")
        hits = [k for k in known if rx.match(k)]
    else:
        hits = [k for k in known if k.endswith("/" + path)]
    return hits[0] if len(hits) == 1 else None


def report(conn: sqlite3.Connection, project: str, snap: int, truth: dict) -> dict:
    files = {
        r["path"]: r
        for r in conn.execute(
            "SELECT u.path, u.id FROM unit_versions uv JOIN units u ON u.id = uv.unit_id "
            "WHERE uv.snapshot_id = ? AND u.kind = 'file'", (snap,))
    }
    covered = {
        r[0]
        for r in conn.execute(
            """SELECT uv.unit_id FROM unit_versions uv
               JOIN coverage c ON c.unit_id = uv.unit_id AND c.content_hash = uv.content_hash
               WHERE uv.snapshot_id = ? AND c.status IN ('clean', 'hypotheses')""", (snap,))
    }
    functions_by_path: dict[str, list[int]] = {}
    for r in conn.execute(
        "SELECT u.path, u.id FROM unit_versions uv JOIN units u ON u.id = uv.unit_id "
        "WHERE uv.snapshot_id = ? AND u.kind = 'function'", (snap,)):
        functions_by_path.setdefault(r["path"], []).append(r["id"])
    findings = conn.execute(
        "SELECT * FROM findings WHERE project = ? AND snapshot_id = ? ORDER BY id",
        (project, snap)).fetchall()
    locations = {
        f["id"]: conn.execute(
            "SELECT l.path, l.start_line, l.unit_id, u.kind FROM finding_locations l "
            "LEFT JOIN units u ON u.id = l.unit_id WHERE l.finding_id = ?", (f["id"],)).fetchall()
        for f in findings
    }

    from .ledger import _unit_at  # local: ledger imports nothing from here

    rows, matched_findings = [], set()
    for item in truth["items"]:
        resolved = [p for p in (_resolve(f, set(files)) for f in item["files"]) if p]
        site = item.get("site")
        site_path = _resolve(site["path"], set(files)) if site else None
        site_unit = _unit_at(conn, snap, site_path, site["line"]) if site_path else None
        site_is_fn = site_unit is not None and site_unit not in {r["id"] for r in files.values()}
        if site_is_fn:
            examined = "yes" if site_unit in covered else "no"
        else:
            fns = [u for p in resolved for u in functions_by_path.get(p, [])]
            examined = f"{sum(u in covered for u in fns)}/{len(fns)}" if fns else "-"
        matches = []
        for f in findings:
            best = None
            for loc in locations[f["id"]]:
                if site_is_fn and loc["unit_id"] == site_unit:
                    best = "unit"
                    break
                # "near" only when the site isn't inside a function (a global,
                # a macro); otherwise a different function is just "file".
                if (site_path and not site_is_fn and loc["path"] == site_path
                        and abs(loc["start_line"] - site["line"]) <= NEAR_LINES):
                    best = "near"
                elif loc["path"] in resolved and best is None:
                    best = "file"
            if best:
                matches.append({"slug": f["slug"], "status": f["status"], "strength": best})
                if best in RAISED:
                    matched_findings.add(f["slug"])
        rank = {"unit": 0, "near": 1, "file": 2}
        matches.sort(key=lambda m: rank[m["strength"]])
        rows.append({
            "id": item["id"], "verdict": item["verdict"], "cwe": item.get("cwe"),
            # The site, when given, is authoritative for scope: a port bug whose
            # affected_components also name a core file is still a port bug.
            "title": item["title"], "examined": examined,
            "in_scope": bool(site_path) if site else bool(resolved),
            "matches": matches,
        })

    def summarize(verdict: str) -> dict:
        scoped = [r for r in rows if r["verdict"] == verdict and r["in_scope"]]
        raised = [r for r in scoped if any(m["strength"] in RAISED for m in r["matches"])]
        confirmed = [r for r in raised if any(
            m["strength"] in RAISED and m["status"] in CONFIRMED for m in r["matches"])]
        rejected = [r for r in raised if r not in confirmed and all(
            m["status"] == "rejected" for m in r["matches"] if m["strength"] in RAISED)]
        return {"in_scope": len(scoped), "raised": len(raised), "confirmed": len(confirmed),
                "rejected": len(rejected)}

    return {
        "truth": truth["name"],
        "items": rows,
        "summary": {v: summarize(v) for v in ("tp", "fp", "unclear")},
        "out_of_scope": sum(not r["in_scope"] for r in rows),
        "unmatched_findings": [
            {"slug": f["slug"], "status": f["status"], "title": f["title"]}
            for f in findings if f["slug"] not in matched_findings
        ],
    }
