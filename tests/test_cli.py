from click.testing import CliRunner

from security_dive import cli
from security_dive.cli import main

from .conftest import commit, git


def test_default_snapshot_and_runs_footer(root, upstream, monkeypatch):
    monkeypatch.chdir(root)
    run = CliRunner().invoke

    assert run(main, ["mirror", "demo"]).exit_code == 0
    r = run(main, ["--ledger", "b", "units", "demo"])
    assert r.exit_code == 0, r.output
    old = git(upstream, "rev-parse", "HEAD")[:12]

    # The default branch moves on; the round's ledger only indexed the old commit.
    (upstream / "src" / "util.c").write_text("int helper(void)\n{\n    return 2;\n}\n")
    commit(upstream, "move on")
    assert run(main, ["mirror", "demo"]).exit_code == 0

    r = run(main, ["--ledger", "b", "coverage", "demo"])
    assert r.exit_code == 0, r.output
    assert old in r.output
    r = run(main, ["coverage", "demo"])  # main ledger indexed nothing
    assert r.exit_code != 0 and "not indexed" in r.output

    for _ in range(2):
        r = run(main, ["--ledger", "b", "next", "demo", "--kind", "dive", "--lens", "memory"])
        assert r.exit_code == 0, r.output
    r = run(main, ["--ledger", "b", "runs", "demo", "--limit", "1"])
    assert "showing the newest 1 of 2 runs" in r.output
    r = run(main, ["--ledger", "b", "runs", "demo", "--limit", "0"])
    assert "showing" not in r.output


def test_todo_minutes_and_kind(root, monkeypatch):
    monkeypatch.chdir(root)
    (root / "projects" / "demo" / "lenses" / "holistic.md").write_text("Everything.\n")
    monkeypatch.setattr(cli.console, "width", 200)
    run = CliRunner().invoke
    assert run(main, ["mirror", "demo"]).exit_code == 0
    assert run(main, ["units", "demo"]).exit_code == 0
    r = run(main, ["todo", "demo", "--kind", "dive", "--minutes", "4"])
    assert r.exit_code == 0, r.output
    assert "runs in 4 min" in r.output and "sweep" not in r.output
    # Two dive runs (one per file) at the 3-minute default: one fits in 4 minutes.
    row = next(line for line in r.output.splitlines() if "holistic" in line)
    assert [c.strip() for c in row.split("│")[3:9]] == ["2", "4", "13", "3.0?", "6", "1"]


def test_run_auto_ranks_first_then_splits_minutes(root, monkeypatch):
    monkeypatch.chdir(root)
    (root / "projects" / "demo" / "lenses" / "holistic.md").write_text("Everything.\n")
    run = CliRunner().invoke
    assert run(main, ["mirror", "demo"]).exit_code == 0
    assert run(main, ["units", "demo"]).exit_code == 0

    ranked, prompts = [], []

    def fake_rank_loop(conn, cfg, project, snap, limit, parallel, min_priority, env, *a, **k):
        rows = cli.rank.unranked(conn, snap, min_priority)
        conn.executemany(
            "INSERT INTO unit_reach (snapshot_id, unit_id, reach, created_at) "
            "VALUES (?, ?, 1, 'now')", [(snap, r["id"]) for r in rows])
        conn.commit()
        ranked.append((len(rows), parallel))
        return {"briefs": 1, "functions": len(rows), "failed": 0, "cost": 0.0,
                "shortened": 0}

    def fake_run(argv, env, cwd, log_dir, meta, out=None):
        prompts.append(meta["prompt"])
        return 0

    monkeypatch.setattr(cli.launch, "rank_loop", fake_rank_loop)
    monkeypatch.setattr(cli.launch, "run", fake_run)
    r = run(main, ["run", "demo", "--minutes", "90"])
    assert r.exit_code == 0, r.output
    assert ranked and ranked[0][0] > 0 and ranked[0][1] == 4
    assert prompts == ["/sdive-sweep demo memory --minutes 60",
                       "/sdive-sweep demo memory --minutes 30"]
    # Everything ranked now: a second auto run goes straight to work.
    r = run(main, ["run", "demo", "--runs", "1"])
    assert r.exit_code == 0 and len(ranked) == 1 and len(prompts) == 3


def test_clusters_and_writeups_when_none(root, monkeypatch):
    monkeypatch.chdir(root)
    run = CliRunner().invoke
    r = run(main, ["clusters", "demo"])
    assert r.exit_code == 0, r.output
    assert "no clusters in demo yet" in r.output and "┏" not in r.output
    r = run(main, ["writeups", "demo"])
    assert r.exit_code == 0, r.output
    assert "no tracked clusters in demo" in r.output and "┏" not in r.output


def test_run_area_ranks_only_that_area(root, monkeypatch):
    monkeypatch.chdir(root)
    (root / "projects" / "demo" / "lenses" / "holistic.md").write_text("Everything.\n")
    run = CliRunner().invoke
    assert run(main, ["mirror", "demo"]).exit_code == 0
    assert run(main, ["units", "demo"]).exit_code == 0
    areas, prompts = [], []
    monkeypatch.setattr(cli.launch, "rank_loop",
                        lambda *a, area=None, **k: areas.append(area))
    monkeypatch.setattr(cli.launch, "run",
                        lambda argv, env, cwd, log_dir, meta, out=None:
                        prompts.append(meta["prompt"]) or 0)
    # misc (priority 1) has nothing to rank, though parsing does: straight to work.
    r = run(main, ["run", "demo", "--area", "misc", "--runs", "1"])
    assert r.exit_code == 0, r.output
    assert areas == [] and prompts == ["/sdive-sweep demo memory 1 --area misc"]
    r = run(main, ["run", "demo", "--area", "parsing", "--runs", "1", "--dry-run"])
    assert "in parsing unranked → sdive rank run all --area parsing" in r.output
    r = run(main, ["run", "demo", "--area", "nosuch"])
    assert r.exit_code != 0 and "unknown area 'nosuch'" in r.output
    r = run(main, ["run", "demo", "verify", "--area", "misc"])
    assert r.exit_code == 2 and "verification is not per area" in r.output
    (root / "projects" / "demo" / "lenses" / "parsers.md").write_text(
        "---\napplies:\n  areas: [parsing]\n---\n# parsers\n")
    r = run(main, ["run", "demo", "sweep", "parsers", "--area", "misc"])
    assert "nothing to do for sweep parsers in area misc" in r.output
