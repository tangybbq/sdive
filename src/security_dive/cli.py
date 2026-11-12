"""sdive — bookkeeping CLI for security-dive. Makes no LLM calls itself; `run` launches
the claude CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import bench as bench_mod
from . import carry as carry_mod
from . import launch, ledger, repo
from .config import MAIN_LEDGER, Config, ConfigError, Project, load_config
from .db import connect
from .schemas import SCHEMAS
from .units import extract_tree

console = Console()
EXIT_NOTHING_TO_DO = 3


class Ctx:
    def __init__(self, ledger: str) -> None:
        self.cfg: Config = load_config().with_ledger(ledger)
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
@click.option("--ledger", envvar="SDIVE_LEDGER", default=MAIN_LEDGER, show_default=True,
              help="Ledger to use: 'main', or a disposable one such as a benchmark round.")
@click.pass_context
def main(ctx: click.Context, ledger: str) -> None:
    """Track deep security analysis of MCUboot and Zephyr."""
    try:
        ctx.obj = Ctx(ledger)
    except ConfigError as e:
        raise click.ClickException(str(e)) from None


def _emit_json(data) -> None:
    click.echo(json.dumps(data, indent=2))


def _snapshot_for(c: Ctx, project: Project, rev: str | None) -> tuple[str, int]:
    """Resolve rev to an indexed snapshot. Without rev: the default branch, or,
    in a ledger that never indexed it (a benchmark round), the ledger's only
    indexed snapshot."""
    if rev is None:
        indexed = c.conn.execute(
            "SELECT id, sha FROM snapshots WHERE project = ? AND indexed_at IS NOT NULL",
            (project.name,)).fetchall()
        sha = repo.resolve(c.cfg, project, project.default_branch)
        if len(indexed) == 1 and indexed[0]["sha"] != sha:
            return indexed[0]["sha"], indexed[0]["id"]
        return sha, ledger.indexed_snapshot(c.conn, project.name, sha)
    sha = repo.resolve(c.cfg, project, rev)
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
    click.echo(f"analysis: {a}\nwork:     {c.cfg.work}\nledger:   {c.cfg.ledger}\n"
               f"db:       {c.cfg.db_path}")


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
    for path in repo.read_marker(tree).get("absent_references", []):
        click.echo(f"note: reference {path} is not a submodule at {sha[:12]}; skipped", err=True)
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
@click.option("--max-units", default=40, show_default=True, help="Dive batch: max functions.")
@click.option("--max-lines", type=int,
              help=f"Batch line budget (default: dive {ledger.DIVE_MAX_LINES}, "
                   f"sweep {ledger.SWEEP_MAX_LINES}).")
@pass_ctx
def next_(c: Ctx, project: str, kind: str, lens: str | None, rev: str | None,
          area: str | None, max_units: int, max_lines: int | None) -> None:
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
        run_id = ledger.next_unit_run(c.conn, p, snap, kind, lens, area, max_units,
                                          max_lines)
    if run_id is None:
        click.echo("nothing to do", err=True)
        sys.exit(EXIT_NOTHING_TO_DO)
    _emit_json(ledger.write_brief(c.conn, c.cfg, run_id))


def _ledger_conns(cfg: Config) -> list:
    """Connections to every ledger (main and disposable), for pooled statistics."""
    paths = [cfg.with_ledger(MAIN_LEDGER).db_path]
    paths += sorted((cfg.analysis / "ledgers").glob("*/sdive.db"))
    return [connect(p) for p in paths if p.exists()]


@main.command()
@click.argument("project")
@click.option("--rev", help="Snapshot revision (default: the default branch).")
@click.option("--lens", "only", multiple=True, help="Only these lenses (repeatable).")
@click.option("--area", help="Only this area.")
@click.option("--kind", "kinds", multiple=True, type=click.Choice(["dive", "sweep", "verify"]),
              help="Only these run kinds (repeatable).")
@click.option("--minutes", type=float,
              help="Also show how many runs of each fit in this many agent-minutes.")
@click.option("--detail", is_flag=True, help="List every estimated run.")
@pass_ctx
def todo(c: Ctx, project: str, rev: str | None, only: tuple[str, ...], area: str | None,
         kinds: tuple[str, ...], minutes: float | None, detail: bool) -> None:
    """Estimate the work left: runs per lens as `next` would hand them out,
    and agent-minutes (median run time, pooled over every ledger).

    Dives use the holistic lens; sweeps every other lens. Agent-minutes track
    cost (parallel runs add up; they only save wall-clock time). Use --minutes
    to size a session, e.g. `/sdive-dive <project> --minutes 40`.
    """
    p = c.project(project)
    sha, snap = _snapshot_for(c, p, rev)
    per_run = ledger.run_minutes(_ledger_conns(c.cfg), p.name)
    plan = [("dive", "holistic")] + [("sweep", n) for n in ledger.available_lenses(p)
                                     if n != "holistic"]
    if only:
        plan = [(k, n) for k, n in plan if n in only]
    if kinds:
        plan = [(k, n) for k, n in plan if k in kinds]
    t = Table(title=f"{project} @ {sha[:12]} — work left")
    cols = ["kind", "lens", "runs", "functions", "lines", "min/run", "agent-min"]
    if minutes:
        cols.append(f"runs in {minutes:g} min")
    cols.append("next run")
    for col in cols:
        t.add_column(col, justify="left" if col in ("kind", "lens", "next run") else "right")

    def est(kind: str, n: int) -> list[str]:
        m, samples = per_run[kind]
        cells = [f"{m:.1f}" + ("" if samples >= 5 else "?"), f"{n * m:.0f}"]
        if minutes:
            cells.append(str(min(n, max(1, int(minutes // m))) if n else 0))
        return cells

    details = []
    for kind, lens in plan:
        runs = ledger.queue_estimate(c.conn, p, snap, kind, lens, area)
        nxt = ""
        if runs:
            r0 = runs[0]
            nxt = (r0["paths"][0] if kind == "dive" else ", ".join(r0["areas"]))
        t.add_row(kind, lens, str(len(runs)), str(sum(r["functions"] for r in runs)),
                  str(sum(r["lines"] for r in runs)), *est(kind, len(runs)), nxt)
        details += [(kind, lens, i, r) for i, r in enumerate(runs, 1)]
    hyps = c.conn.execute(
        "SELECT count(*) FROM findings WHERE project = ? AND status = 'hypothesis'",
        (p.name,)).fetchone()[0]
    if not kinds or "verify" in kinds:
        t.add_row("verify", "", str(hyps), "", "", *est("verify", hyps), "")
    console.print(t)
    click.echo("min/run: median of recorded runs ('?' = fewer than 5 samples). "
               "Agent-minutes add up across parallel runs.")
    started = c.conn.execute(
        "SELECT count(*) FROM runs WHERE project = ? AND status = 'started'",
        (p.name,)).fetchone()[0]
    if started:
        click.echo(f"runs started but not recorded: {started} "
                   f"(`sdive runs {project} --status started`; record or abandon them)")
    if detail:
        for kind, lens, i, r in details:
            where = r["paths"][0] if kind == "dive" else ", ".join(r["areas"])
            click.echo(f"{kind:5} {lens:16} #{i:<3} {r['functions']:4} fn {r['lines']:6} lines"
                       f"  {where}")


@main.command("run")
@click.argument("project")
@click.argument("kind", required=False, type=click.Choice(["auto", "verify", "sweep", "dive"]),
                default="auto")
@click.argument("lens", required=False)
@click.option("--runs", type=int, help="Number of runs (default 1 unless --minutes).")
@click.option("--minutes", type=float, help="Budget in agent-minutes (see `sdive todo`).")
@click.option("--parallel", type=click.IntRange(1, 4), default=1, show_default=True)
@click.option("--model", envvar="SDIVE_MODEL", default=launch.DEFAULT_MODEL, show_default=True)
@click.option("-i", "--interactive", is_flag=True,
              help="Open an interactive session instead of running headless (-p).")
@click.option("--keep-api-key", is_flag=True,
              help="Pass ANTHROPIC_API_KEY through (bills the API, not the plan).")
@click.option("--dry-run", is_flag=True, help="Print the claude command; don't run it.")
@pass_ctx
def run_(c: Ctx, project: str, kind: str, lens: str | None, runs: int | None,
         minutes: float | None, parallel: int, model: str, interactive: bool,
         keep_api_key: bool, dry_run: bool) -> None:
    """Launch Claude Code on the next piece of work (or KIND [LENS]).

    auto: verify pending hypotheses, else the next lens in the project's
    sweep_order with sweep work left, else dives. Runs headless with
    progress streamed; the session log and its reported cost are saved under
    the ledger's sessions/ directory. Examples:

      sdive run mcuboot --minutes 40
      sdive run mcuboot sweep memory-safety --runs 2
      sdive run mcuboot dive --runs 1 --dry-run
    """
    if runs and minutes:
        raise click.UsageError("give --runs or --minutes, not both")
    p = c.project(project)
    _sha, snap = _snapshot_for(c, p, None)
    pending = c.conn.execute(
        "SELECT count(*) FROM findings WHERE project = ? AND status = 'hypothesis'",
        (p.name,)).fetchone()[0]
    order = p.sweep_order or tuple(n for n in ledger.available_lenses(p) if n != "holistic")
    plan = launch.choose(None if kind == "auto" else kind, lens, pending,
                         lambda n: len(ledger.queue_estimate(c.conn, p, snap, "sweep", n)),
                         order)
    if plan is None:
        click.echo(f"nothing to do for {kind}" + (f" {lens}" if lens else ""))
        sys.exit(EXIT_NOTHING_TO_DO)
    prompt = launch.invocation(plan, p.name, c.cfg.ledger, runs, minutes, parallel)
    argv = launch.command(prompt, model, headless=not interactive, staging=c.cfg.staging)
    click.echo(f"{plan.reason} → {prompt}")
    if dry_run:
        click.echo(" ".join(_shell_quote(a) for a in argv))
        return
    env = launch.child_env(keep_api_key)
    if interactive:
        os.chdir(c.cfg.root)
        os.execvpe(argv[0], argv, env)
    status = launch.run(argv, env, c.cfg.root, c.cfg.ledger_dir / "sessions",
                        {"project": p.name, "ledger": c.cfg.ledger, "model": model,
                         "prompt": prompt})
    sys.exit(status)


def _shell_quote(arg: str) -> str:
    import shlex
    return shlex.quote(arg)


@main.command("brief")
@click.argument("run_id", type=int)
@pass_ctx
def brief_(c: Ctx, run_id: int) -> None:
    """Print (and rewrite to staging) the brief for an existing run."""
    _emit_json(ledger.write_brief(c.conn, c.cfg, run_id))


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
    for title in r.upstream:
        click.echo(f"  upstream note: {title}")


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
@click.option("--limit", default=30, show_default=True, help="0 for all.")
@pass_ctx
def runs(c: Ctx, project: str, status: str | None, limit: int) -> None:
    """List recent runs, newest first."""
    total = c.conn.execute(
        "SELECT count(*) FROM runs WHERE project = ? AND (? IS NULL OR status = ?)",
        (project, status, status)).fetchone()[0]
    rows = c.conn.execute(
        """SELECT r.*, l.name AS lens, s.sha,
                  (SELECT count(*) FROM run_targets t WHERE t.run_id = r.id) AS ntargets
           FROM runs r LEFT JOIN lenses l ON l.id = r.lens_id
           LEFT JOIN snapshots s ON s.id = r.snapshot_id
           WHERE r.project = ? AND (? IS NULL OR r.status = ?)
           ORDER BY r.id DESC LIMIT ?""",
        (project, status, status, limit or -1),
    ).fetchall()
    t = Table()
    for col in ("id", "kind", "lens", "status", "targets", "sha", "model", "started"):
        t.add_column(col)
    for r in rows:
        t.add_row(str(r["id"]), r["kind"], r["lens"] or "", r["status"], str(r["ntargets"]),
                  (r["sha"] or "")[:12], r["model"] or "", r["started_at"])
    console.print(t)
    if len(rows) < total:
        click.echo(f"showing the newest {len(rows)} of {total} runs; --limit 0 for all")


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


@main.command()
@click.argument("project")
@click.option("--json", "as_json", is_flag=True, help="Full records as JSON.")
@pass_ctx
def upstream(c: Ctx, project: str, as_json: bool) -> None:
    """List suspected defects noted in external (reference) components."""
    rows = c.conn.execute(
        "SELECT * FROM upstream_notes WHERE project = ? ORDER BY id", (project,)
    ).fetchall()
    if as_json:
        _emit_json([dict(r, locations=json.loads(r["locations"])) for r in rows])
        return
    t = Table()
    for col in ("id", "component", "sha", "status", "run", "title"):
        t.add_column(col)
    for r in rows:
        t.add_row(str(r["id"]), r["component"], (r["component_sha"] or "")[:12], r["status"],
                  str(r["run_id"]), r["title"])
    console.print(t)


@main.command()
@click.argument("project")
@click.option("--from", "source", required=True, help="Ledger to carry findings from.")
@click.option("--rev", help="Target snapshot (default: the default branch).")
@click.option("--status", "statuses", multiple=True,
              help="Source statuses to carry (repeatable; default: verified).")
@click.option("--slug", "slugs", multiple=True, help="Only these source findings.")
@click.option("--dry-run", is_flag=True, help="Show the mapping; change nothing.")
@pass_ctx
def carry(c: Ctx, project: str, source: str, rev: str | None, statuses: tuple[str, ...],
          slugs: tuple[str, ...], dry_run: bool) -> None:
    """Carry findings from another ledger into this one, as hypotheses at REV.

    E.g. `sdive carry mcuboot --from bench-vanessa-20261112` re-queues a
    round's verified findings for blind verification against current `main`.
    Locations are remapped through function keys; the "code" column says
    whether the functions involved are unchanged, changed, or gone.
    """
    p = c.project(project)
    if source == c.cfg.ledger:
        raise click.UsageError("--from must name a different ledger")
    src_cfg = c.cfg.with_ledger(source)
    if not src_cfg.db_path.exists():
        raise click.ClickException(f"no ledger {source!r} ({src_cfg.db_path})")
    sha, snap = _snapshot_for(c, p, rev)
    rows = carry_mod.carry(connect(src_cfg.db_path), source, c.conn, p.name, snap,
                           statuses or carry_mod.DEFAULT_STATUSES, list(slugs) or None,
                           dry_run, tree_for=lambda s: c.cfg.snapshot_path(p.name, s))
    t = Table(title=f"{source} -> {c.cfg.ledger} @ {sha[:12]}" + (" (dry run)" if dry_run else ""))
    for col in ("source", "status", "code", "locations", "result"):
        t.add_column(col, overflow="fold")
    for r in rows:
        states = defaultdict(int)
        for loc in r["locations"]:
            states[loc["state"]] += 1
        result = r["skipped"] or (f"+ {r['slug']}" if r["slug"] else "would carry")
        t.add_row(r["source"], r["status"], r["code"],
                  ", ".join(f"{n} {k}" for k, n in sorted(states.items())), result)
    console.print(t)
    n = sum(1 for r in rows if r["slug"])
    if n:
        click.echo(f"{n} carried as hypotheses; verify with /sdive-verify {project} all"
                   + ("" if c.cfg.ledger == MAIN_LEDGER else f" --ledger {c.cfg.ledger}"))


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


@main.group()
def bench() -> None:
    """Benchmark a ledger against known ground truth (human use only)."""


@bench.command("import")
@click.argument("project")
@click.argument("corpus", nargs=-1, required=True,
                type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--name", required=True, help="Truth set name, e.g. vanessa.")
@pass_ctx
def bench_import(c: Ctx, project: str, corpus: tuple[Path, ...], name: str) -> None:
    """Import ground truth from zepsec-style analysis directories."""
    c.project(project)
    data = bench_mod.save_truth(c.cfg, project, name, list(corpus))
    counts = defaultdict(int)
    for item in data["items"]:
        counts[item["verdict"]] += 1
    click.echo(f"{bench_mod.truth_path(c.cfg, project, name)}: {len(data['items'])} items "
               f"({', '.join(f'{k} {v}' for k, v in sorted(counts.items()))})")


@bench.command("report")
@click.argument("project")
@click.argument("name")
@click.option("--rev", required=True, help="The commit the truth set was validated at.")
@click.option("--json", "as_json", is_flag=True)
@pass_ctx
def bench_report(c: Ctx, project: str, name: str, rev: str, as_json: bool) -> None:
    """Score this ledger's findings at REV against truth set NAME."""
    p = c.project(project)
    path = bench_mod.truth_path(c.cfg, project, name)
    if not path.exists():
        raise click.ClickException(f"no truth set {path}; run `sdive bench import`")
    sha, snap = _snapshot_for(c, p, rev)
    judgments = bench_mod.load_judgments(c.cfg, name)
    r = bench_mod.report(c.conn, p.name, snap, json.loads(path.read_text()), judgments)
    if as_json:
        _emit_json(r)
        return
    t = Table(title=f"{project} @ {sha[:12]} — ledger {c.cfg.ledger} vs {name}")
    for col in ("id", "truth", "cwe", "examined", "judged hits / candidates", "title"):
        t.add_column(col, overflow="fold")
    for row in r["items"]:
        if not row["in_scope"] and not row["hits"]:
            continue
        if row["hits"] is not None:
            ms = "judged: " + (" ".join(f"{h['slug']}({h['status']})" for h in row["hits"])
                               or "none")
        else:
            ms = " ".join(f"{m['slug']}({m['strength']}:{m['status']})"
                          for m in row["matches"])
        t.add_row(row["id"] + ("" if row["in_scope"] else " (out of scope)"), row["verdict"],
                  row["cwe"] or "", row["examined"], ms, row["title"][:60])
    console.print(t)
    s = r["summary"]
    def pending(k: str) -> str:
        n = s[k]["pending"]
        return f"; {n} with candidates awaiting judgement" if n else ""
    click.echo(f"true positives in scope: {s['tp']['in_scope']}; raised {s['tp']['raised']}, "
               f"confirmed by verifier {s['tp']['confirmed']}{pending('tp')}")
    click.echo(f"refuted claims (traps) in scope: {s['fp']['in_scope']}; raised "
               f"{s['fp']['raised']}, wrongly confirmed {s['fp']['confirmed']}, rejected "
               f"{s['fp']['rejected']}{pending('fp')}")
    click.echo(f"unclear in scope: {s['unclear']['in_scope']}; raised "
               f"{s['unclear']['raised']}{pending('unclear')}")
    click.echo(f"out of scope: {r['out_of_scope']}")
    if r["unknown_judged_items"]:
        unknown = ", ".join(r["unknown_judged_items"])
        click.echo(f"warning: judgements name unknown items: {unknown}")
    if r["unmatched_findings"]:
        click.echo(f"findings not judged to raise any truth item "
                   f"({len(r['unmatched_findings'])}) — new bugs, false positives, or "
                   "still to judge:")
        for f in r["unmatched_findings"]:
            cand = (f" (candidate for {', '.join(f['candidate_for'])})"
                    if f["candidate_for"] else "")
            click.echo(f"  {f['slug']} [{f['status']}] {f['title']}{cand}")


@bench.command("judge")
@click.argument("project")
@click.argument("name")
@click.argument("item")
@click.argument("slugs", nargs=-1)
@click.option("--none", "none_", is_flag=True, help="No finding raises this item.")
@click.option("--clear", is_flag=True, help="Forget the judgement for this item.")
@click.option("--note", help="Why (kept in adjudication.json).")
@pass_ctx
def bench_judge(c: Ctx, project: str, name: str, item: str, slugs: tuple[str, ...],
                none_: bool, clear: bool, note: str | None) -> None:
    """Record which findings of this ledger actually raise truth ITEM.

    Replaces any earlier judgement of ITEM. Give the finding slugs, or --none,
    or --clear. Human use, after a round is finished.
    """
    if sum([bool(slugs), none_, clear]) != 1:
        raise click.UsageError("give finding slugs, or exactly one of --none / --clear")
    p = c.project(project)
    path = bench_mod.truth_path(c.cfg, project, name)
    if not path.exists():
        raise click.ClickException(f"no truth set {path}; run `sdive bench import`")
    ids = {i["id"] for i in json.loads(path.read_text())["items"]}
    if item not in ids:
        raise click.ClickException(f"{name} has no item {item!r}")
    known = {r[0] for r in c.conn.execute(
        "SELECT slug FROM findings WHERE project = ?", (p.name,))}
    if missing := sorted(set(slugs) - known):
        raise click.ClickException(f"no such finding(s) in ledger {c.cfg.ledger}: "
                                   + ", ".join(missing))
    bench_mod.judge(c.cfg, name, item, None if clear else list(slugs), note)
    what = "cleared" if clear else ("none" if none_ else ", ".join(slugs))
    click.echo(f"{name} {item}: {what}")


@main.command()
@click.argument("kind", type=click.Choice(sorted(SCHEMAS)))
def schema(kind: str) -> None:
    """Print the JSON schema a run result must satisfy."""
    _emit_json(SCHEMAS[kind].model_json_schema())
