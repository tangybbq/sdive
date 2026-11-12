"""sdive — bookkeeping CLI for security-dive. Makes no LLM calls."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import ledger, repo
from .config import Config, ConfigError, Project, load_config
from .db import connect
from .schemas import SCHEMAS
from .units import extract_tree

console = Console()
EXIT_NOTHING_TO_DO = 3


class Ctx:
    def __init__(self) -> None:
        self.cfg: Config = load_config()
        self._conn = None

    @property
    def conn(self):
        if self._conn is None:
            self._conn = connect(self.cfg.db_path)
        return self._conn

    def project(self, name: str) -> Project:
        return self.cfg.project(name)


pass_ctx = click.make_pass_decorator(Ctx)


class Group(click.Group):
    """Turn expected errors into clean messages instead of tracebacks."""

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except (ConfigError, ledger.LedgerError, repo.GitError) as e:
            raise click.ClickException(str(e)) from None


@click.group(cls=Group)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Track deep security analysis of MCUboot and Zephyr."""
    try:
        ctx.obj = Ctx()
    except ConfigError as e:
        raise click.ClickException(str(e)) from None


def _emit_json(data) -> None:
    click.echo(json.dumps(data, indent=2))


def _snapshot_for(c: Ctx, project: Project, rev: str | None) -> tuple[str, int]:
    """Resolve rev (default: the project's default branch) to an indexed snapshot."""
    sha = repo.resolve(c.cfg, project, rev or project.default_branch)
    return sha, ledger.indexed_snapshot(c.conn, project.name, sha)


# --- setup -----------------------------------------------------------------


@main.command()
@pass_ctx
def init(c: Ctx) -> None:
    """Create analysis/ (a private nested git repo) and work/, and the database."""
    a = c.cfg.analysis
    for d in (a, c.cfg.staging, c.cfg.work):
        d.mkdir(parents=True, exist_ok=True)
    if not (a / ".git").exists():
        subprocess.run(["git", "init", "-q", "-b", "main", str(a)], check=True)
        (a / ".gitignore").write_text("staging/\n*.db-wal\n*.db-shm\n")
    _ = c.conn  # creates/migrates the database
    click.echo(f"analysis: {a}\nwork:     {c.cfg.work}\ndb:       {c.cfg.db_path}")


@main.command()
@pass_ctx
def projects(c: Ctx) -> None:
    """List configured projects."""
    for name, p in c.cfg.projects.items():
        scope = "scope defined" if p.include else "no scope yet"
        click.echo(f"{name:10} {p.github:28} {len(p.areas):2} areas, {scope}")


@main.command()
@click.argument("project")
@click.option("--no-fetch", is_flag=True, help="Create if missing, but don't fetch.")
@pass_ctx
def mirror(c: Ctx, project: str, no_fetch: bool) -> None:
    """Create or update the project's private bare mirror."""
    p = c.project(project)
    path = repo.ensure_mirror(c.cfg, p, fetch=not no_fetch)
    head = repo.resolve(c.cfg, p, p.default_branch)
    click.echo(f"{path}\n{p.default_branch} = {head}")


@main.command()
@click.argument("project")
@click.argument("rev", required=False)
@pass_ctx
def snapshot(c: Ctx, project: str, rev: str | None) -> None:
    """Export a read-only snapshot of REV (default: the default branch)."""
    p = c.project(project)
    sha = repo.resolve(c.cfg, p, rev or p.default_branch)
    click.echo(repo.snapshot(c.cfg, p, sha))


@main.command()
@click.argument("project")
@click.argument("rev", required=False)
@click.option("--list", "show", is_flag=True, help="List every unit.")
@pass_ctx
def units(c: Ctx, project: str, rev: str | None, show: bool) -> None:
    """Snapshot REV and index its units (files and functions) by area."""
    p = c.project(project)
    if not p.include:
        raise click.ClickException(f"{project}: no scope in {p.defdir / 'project.toml'}")
    ref = rev or p.default_branch
    sha = repo.resolve(c.cfg, p, ref)
    tree = repo.snapshot(c.cfg, p, sha)
    found = extract_tree(p, tree)
    snap = ledger.snapshot_id(c.conn, p.name, sha, ref)
    ledger.index_units(c.conn, p.name, snap, found)

    if show:
        for u in found:
            click.echo(f"{u.area:18} {u.kind:8} {u.key}  [{u.start_line}-{u.end_line}]")
        return
    stats: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    for u in found:
        s = stats[u.area]
        s[0] = max(s[0], u.priority)
        if u.kind == "file":
            s[1] += 1
            s[3] += u.end_line
        else:
            s[2] += 1
    t = Table(title=f"{project} @ {sha[:12]} ({ref})")
    for col in ("area", "prio", "files", "functions", "lines"):
        t.add_column(col, justify="left" if col == "area" else "right")
    ordered = sorted(stats.items(), key=lambda kv: (-kv[1][0], kv[0]))
    for area, (prio, files, funcs, lines) in ordered:
        t.add_row(area, str(prio), str(files), str(funcs), str(lines))
    totals = (str(sum(s[i] for s in stats.values())) for i in (1, 2, 3))
    t.add_row("total", "", *totals, style="bold")
    console.print(t)


@main.command()
@click.argument("project")
@pass_ctx
def lenses(c: Ctx, project: str) -> None:
    """List the project's lenses and their current content hashes."""
    p = c.project(project)
    names = ledger.available_lenses(p)
    if not names:
        click.echo(f"no lenses in {p.lenses_dir}")
    for name in names:
        click.echo(f"{name:28} {ledger.file_hash(ledger.lens_path(p, name))}")


# --- the work loop ---------------------------------------------------------


@main.command("next")
@click.argument("project")
@click.option("--kind", type=click.Choice(["dive", "sweep", "verify"]), required=True)
@click.option("--lens", help="Lens name (required for dive and sweep).")
@click.option("--rev", help="Snapshot revision (default: the default branch).")
@click.option("--area", help="Restrict dive/sweep to one area.")
@click.option("--max-units", default=40, show_default=True, help="Dive batch size cap.")
@pass_ctx
def next_(c: Ctx, project: str, kind: str, lens: str | None, rev: str | None,
          area: str | None, max_units: int) -> None:
    """Start a run on the next piece of work and print its brief as JSON.

    Exits with status 3 when there is nothing left to do.
    """
    p = c.project(project)
    if kind == "verify":
        run_id = ledger.next_verify_run(c.conn, p)
    else:
        if not lens:
            raise click.UsageError(f"--lens is required for --kind {kind}")
        _sha, snap = _snapshot_for(c, p, rev)
        run_id = ledger.next_unit_run(c.conn, p, snap, kind, lens, area, max_units)
    if run_id is None:
        click.echo("nothing to do", err=True)
        sys.exit(EXIT_NOTHING_TO_DO)
    c.cfg.staging.mkdir(parents=True, exist_ok=True)
    _emit_json(ledger.brief(c.conn, c.cfg, run_id))


@main.command("brief")
@click.argument("run_id", type=int)
@pass_ctx
def brief_(c: Ctx, run_id: int) -> None:
    """Print the brief for an existing run."""
    _emit_json(ledger.brief(c.conn, c.cfg, run_id))


@main.command("record")
@click.argument("run_id", type=int)
@click.option("--file", "path", type=click.Path(path_type=Path),
              help="Result JSON (default: the run's staging path).")
@pass_ctx
def record_(c: Ctx, run_id: int, path: Path | None) -> None:
    """Validate a run's result JSON and apply it to the ledger."""
    path = path or c.cfg.staging / f"run-{run_id}.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        raise click.ClickException(f"no result file at {path}") from None
    except json.JSONDecodeError as e:
        raise click.ClickException(f"{path}: invalid JSON: {e}") from None
    r = ledger.record(c.conn, c.cfg, run_id, data)
    if path.is_relative_to(c.cfg.staging):
        path.unlink()
    if r.kind == "verify":
        click.echo(f"run {run_id}: {r.findings[0]} -> {r.verdict}")
    else:
        click.echo(f"run {run_id}: {r.covered} covered, {r.partial} partial, "
                   f"{len(r.findings)} new hypotheses")
        for slug in r.findings:
            click.echo(f"  + {slug}")
        if r.missing:
            click.echo(f"  {len(r.missing)} target(s) not reported (left uncovered):")
            for key in r.missing:
                click.echo(f"    {key}")
    if r.dossiers:
        click.echo(f"  dossiers updated: {', '.join(r.dossiers)}")


@main.command()
@click.argument("run_id", type=int)
@pass_ctx
def abandon(c: Ctx, run_id: int) -> None:
    """Release a started run's targets without recording anything."""
    ledger.abandon(c.conn, run_id)
    click.echo(f"run {run_id} abandoned")


@main.command()
@click.argument("project")
@click.option("--status", type=click.Choice(["started", "recorded", "abandoned"]))
@click.option("--limit", default=30, show_default=True)
@pass_ctx
def runs(c: Ctx, project: str, status: str | None, limit: int) -> None:
    """List recent runs."""
    rows = c.conn.execute(
        """SELECT r.*, l.name AS lens, s.sha,
                  (SELECT count(*) FROM run_targets t WHERE t.run_id = r.id) AS ntargets
           FROM runs r LEFT JOIN lenses l ON l.id = r.lens_id
           LEFT JOIN snapshots s ON s.id = r.snapshot_id
           WHERE r.project = ? AND (? IS NULL OR r.status = ?)
           ORDER BY r.id DESC LIMIT ?""",
        (project, status, status, limit),
    ).fetchall()
    t = Table()
    for col in ("id", "kind", "lens", "status", "targets", "sha", "model", "started"):
        t.add_column(col)
    for r in rows:
        t.add_row(str(r["id"]), r["kind"], r["lens"] or "", r["status"], str(r["ntargets"]),
                  (r["sha"] or "")[:12], r["model"] or "", r["started_at"])
    console.print(t)


# --- reports and findings ----------------------------------------------------


@main.command()
@click.argument("project")
@click.option("--rev", help="Snapshot revision (default: the default branch).")
@click.option("--lens", help="Only count coverage under this lens.")
@click.option("--any-version", is_flag=True, help="With --lens: count older lens versions too.")
@pass_ctx
def coverage(c: Ctx, project: str, rev: str | None, lens: str | None, any_version: bool) -> None:
    """Per-area function coverage at a snapshot (current content hashes only)."""
    p = c.project(project)
    sha, snap = _snapshot_for(c, p, rev)
    lens_ids = None
    if lens:
        if any_version:
            lens_ids = [r[0] for r in c.conn.execute(
                "SELECT id FROM lenses WHERE project = ? AND name = ?", (p.name, lens))]
        else:
            lens_ids = [ledger.register_lens(c.conn, p, lens)]
    rows = ledger.coverage_by_area(c.conn, snap, lens_ids)
    t = Table(title=f"{project} @ {sha[:12]}" + (f" — lens {lens}" if lens else " — any lens"))
    for col in ("area", "prio", "functions", "lines", "swept", "dived"):
        t.add_column(col, justify="left" if col == "area" else "right")
    def pct(n: int, d: int) -> str:
        return f"{n} ({100 * n // d}%)" if d else "0"
    tot = defaultdict(int)
    for r in rows:
        t.add_row(r["area"], str(r["priority"]), str(r["functions"]), str(r["lines"]),
                  pct(r["swept"], r["functions"]), pct(r["dived"], r["functions"]))
        for k in ("functions", "lines", "swept", "dived"):
            tot[k] += r[k]
    t.add_row("total", "", str(tot["functions"]), str(tot["lines"]),
              pct(tot["swept"], tot["functions"]), pct(tot["dived"], tot["functions"]),
              style="bold")
    console.print(t)


@main.command()
@click.argument("project")
@click.option("--status")
@pass_ctx
def findings(c: Ctx, project: str, status: str | None) -> None:
    """List findings."""
    rows = c.conn.execute(
        "SELECT * FROM findings WHERE project = ? AND (? IS NULL OR status = ?) ORDER BY id",
        (project, status, status),
    ).fetchall()
    t = Table()
    for col in ("slug", "status", "prop", "atk", "cwe", "conf", "title"):
        t.add_column(col)
    for f in rows:
        t.add_row(f["slug"], f["status"], f["property"] or "", f["attacker"] or "",
                  f["cwe"] or "", f["confidence"] or "", f["title"])
    console.print(t)


@main.group()
def finding() -> None:
    """Inspect or update one finding."""


@finding.command("show")
@click.argument("slug")
@pass_ctx
def finding_show(c: Ctx, slug: str) -> None:
    """Show a finding with its locations and history, as JSON."""
    f = c.conn.execute("SELECT * FROM findings WHERE slug = ?", (slug,)).fetchone()
    if f is None:
        raise click.ClickException(f"no finding {slug!r}")
    out = dict(f)
    out["locations"] = ledger._finding_locations(c.conn, f["id"])
    out["events"] = [dict(e) for e in c.conn.execute(
        "SELECT at, run_id, from_status, to_status, note FROM finding_events "
        "WHERE finding_id = ? ORDER BY id", (f["id"],))]
    _emit_json(out)


@finding.command("set")
@click.argument("slug")
@click.option("--status", required=True, type=click.Choice(sorted(ledger.TRANSITIONS)))
@click.option("--note")
@pass_ctx
def finding_set(c: Ctx, slug: str, status: str, note: str | None) -> None:
    """Move a finding through its lifecycle (e.g. verified -> exported)."""
    old, new = ledger.set_finding_status(c.conn, slug, status, note)
    click.echo(f"{slug}: {old} -> {new}")


@main.command()
@click.argument("kind", type=click.Choice(sorted(SCHEMAS)))
def schema(kind: str) -> None:
    """Print the JSON schema a run result must satisfy."""
    _emit_json(SCHEMAS[kind].model_json_schema())
