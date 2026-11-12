from click.testing import CliRunner

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
