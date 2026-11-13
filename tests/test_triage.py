"""Clusters, manual duplicates and release scoping."""

import pytest

from security_dive import ledger, repo, triage
from security_dive.db import connect
from security_dive.units import extract_tree

from .conftest import commit, git


@pytest.fixture
def scoped(cfg, upstream):
    """Upstream released as v1.0.0 (plus an -rc tag that must not count), then
    util.c's helper changed after the release; snapshot at the new main."""
    git(upstream, "tag", "v1.0.0")
    (upstream / "src" / "util.c").write_text("int helper(void)\n{\n    return 2;\n}\n")
    commit(upstream, "change helper")
    git(upstream, "tag", "v1.1.0-rc1")
    p = cfg.project("demo")
    mirror = repo.ensure_mirror(cfg, p)
    sha = repo.resolve(cfg, p, "main")
    tree = repo.snapshot(cfg, p, sha)
    conn = connect(cfg.db_path)
    snap = ledger.snapshot_id(conn, p.name, sha, "main")
    ledger.index_units(conn, p.name, snap, extract_tree(p, tree))
    return conn, snap, mirror


def add_finding(conn, snap, slug, locs, status="verified"):
    cur = conn.execute(
        "INSERT INTO findings (project, slug, title, status, claim, property, snapshot_id, "
        "created_at, updated_at) VALUES ('demo', ?, ?, ?, 'c', 'P6', ?, 'now', 'now')",
        (slug, slug.upper(), status, snap))
    for path, start, end in locs:
        conn.execute("INSERT INTO finding_locations (finding_id, path, start_line, end_line) "
                     "VALUES (?, ?, ?, ?)", (cur.lastrowid, path, start, end))
    conn.commit()
    return cur.lastrowid


def test_release_scoping(scoped):
    conn, snap, mirror = scoped
    add_finding(conn, snap, "old", [("src/parser.c", 3, 6)])
    add_finding(conn, snap, "new", [("src/util.c", 3, 3)])
    add_finding(conn, snap, "both", [("src/parser.c", 5, 5), ("src/util.c", 1, 4)])
    add_finding(conn, snap, "ext", [("ext/lib/library/lib.c", 1, 1)])
    add_finding(conn, snap, "maybe", [("src/util.c", 3, 3)], status="hypothesis")

    rel = triage.Releases(mirror)
    assert rel.tags == ["v1.0.0"]
    ids = triage.scope_targets(conn, "demo", [], redo=False)
    assert len(ids) == 4   # verified only
    out = {r["slug"]: r for r in (triage.scope_finding(conn, mirror, rel, i) for i in ids)}

    assert (out["old"]["verdict"], out["old"]["as_is_since"]) == ("released", "v1.0.0")
    assert out["old"]["latest_release"] == "v1.0.0"
    assert out["new"]["verdict"] == "post-release" and out["new"]["as_is_since"] is None
    assert out["new"]["locations"][0]["commits"][0]["summary"] == "change helper"
    assert out["both"]["verdict"] == "mixed"
    assert (out["both"]["released_lines"], out["both"]["post_release_lines"]) == (4, 1)
    assert out["ext"]["verdict"] == "unknown" and "error" in out["ext"]["locations"][0]

    # Stored; a second pass finds nothing new unless asked to redo.
    assert triage.scope_targets(conn, "demo", [], redo=False) == []
    assert len(triage.scope_targets(conn, "demo", [], redo=True)) == 4
    assert conn.execute("SELECT count(*) FROM finding_scope").fetchone()[0] == 4


def test_clusters(scoped):
    conn, snap, mirror = scoped
    for s in ("a", "b", "c"):
        add_finding(conn, snap, s, [("src/parser.c", 3, 6)])
    add_finding(conn, snap, "h", [("src/parser.c", 3, 6)], status="hypothesis")

    triage.new_cluster(conn, "demo", "parse-len", "Parser length", "one check", ["a", "b"])
    with pytest.raises(ledger.LedgerError, match="already in cluster"):
        triage.new_cluster(conn, "demo", "other", "Other", None, ["b"])
    with pytest.raises(ledger.LedgerError, match="only verified"):
        triage.add_to_cluster(conn, "parse-len", ["h"])
    with pytest.raises(ledger.LedgerError, match="slug"):
        triage.new_cluster(conn, "demo", "Bad Slug", "x", None, ["c"])
    triage.new_cluster(conn, "demo", "other", "Other", None, ["c"])
    triage.add_to_cluster(conn, "other", ["b"], move=True)
    assert [m["slug"] for m in triage.cluster_members(conn, 1)] == ["a"]
    triage.remove_from_cluster(conn, "other", ["b"])
    assert [f["slug"] for f in triage.unclustered(conn, "demo")] == ["b"]

    with pytest.raises(ledger.LedgerError, match="note"):
        triage.set_track(conn, "parse-len", "advisory", " ")
    triage.set_track(conn, "parse-len", "advisory", "in v1.0.0")

    rep = triage.cluster_report(conn, "parse-len")
    assert rep["track"] == "advisory" and rep["scope"] is None   # not scoped yet
    rel = triage.Releases(mirror)
    for i in triage.scope_targets(conn, "demo", [], redo=False):
        triage.scope_finding(conn, mirror, rel, i)
    assert triage.cluster_report(conn, "parse-len")["scope"] == "released"


def test_combine():
    assert triage.combine([]) is None
    assert triage.combine(["released", None]) is None
    assert triage.combine(["released", "released", "unknown"]) == "released"
    assert triage.combine(["released", "post-release"]) == "mixed"
    assert triage.combine(["unknown"]) == "unknown"


def test_manual_duplicate(scoped):
    conn, snap, _ = scoped
    add_finding(conn, snap, "orig", [("src/parser.c", 3, 6)])
    add_finding(conn, snap, "copy", [("src/parser.c", 3, 6)])
    add_finding(conn, snap, "third", [("src/parser.c", 3, 6)])
    triage.new_cluster(conn, "demo", "kk", "K", None, ["orig", "copy"])

    with pytest.raises(ledger.LedgerError, match="--of"):
        ledger.set_finding_status(conn, "copy", "duplicate")
    with pytest.raises(ledger.LedgerError, match="--of"):
        ledger.set_finding_status(conn, "copy", "exported", duplicate_of="orig")
    with pytest.raises(ledger.LedgerError, match="no other"):
        ledger.set_finding_status(conn, "copy", "duplicate", duplicate_of="copy")
    assert ledger.set_finding_status(conn, "copy", "duplicate", "same bug", "orig") == (
        "verified", "duplicate")
    row = conn.execute("SELECT duplicate_of, cluster_id FROM findings WHERE slug = 'copy'"
                       ).fetchone()
    assert (row["duplicate_of"], row["cluster_id"]) == ("orig", None)
    note = conn.execute("SELECT note FROM finding_events ORDER BY id DESC").fetchone()[0]
    assert note == "duplicate of orig: same bug"
    with pytest.raises(ledger.LedgerError, match="itself a duplicate"):
        ledger.set_finding_status(conn, "third", "duplicate", duplicate_of="copy")
