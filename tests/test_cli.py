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
