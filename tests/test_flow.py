"""End to end: mirror -> snapshot -> index -> next -> record -> verify."""

import json
import os

import pytest

from security_dive import ledger, repo
from security_dive.db import connect
from security_dive.units import extract_tree

from .conftest import git


@pytest.fixture
def indexed(cfg):
    p = cfg.project("demo")
    repo.ensure_mirror(cfg, p)
    sha = repo.resolve(cfg, p, "main")
    tree = repo.snapshot(cfg, p, sha)
    conn = connect(cfg.db_path)
    snap = ledger.snapshot_id(conn, p.name, sha, "main")
    ledger.index_units(conn, p.name, snap, extract_tree(p, tree))
    return p, conn, snap, sha, tree


def test_snapshot_is_read_only_and_idempotent(cfg, indexed):
    p, _conn, _snap, sha, tree = indexed
    f = tree / "src" / "parser.c"
    assert not os.access(f, os.W_OK)
    assert (tree / repo.MARKER).exists()
    assert repo.snapshot(cfg, p, sha) == tree


def audit(run_id, units, hypotheses=(), dossier=()):
    return {
        "run_id": run_id,
        "model": "test-model",
        "summary": "looked",
        "units": [{"key": k, "status": s} for k, s in units],
        "hypotheses": list(hypotheses),
        "dossier": list(dossier),
    }


HYP = {
    "title": "parse reads buf[0] when len is 0",
    "claim": "parse dereferences buf without checking len > 0.",
    "locations": [{"path": "src/parser.c", "start_line": 13}],
    "property": "P6",
    "attacker": "A2",
    "confidence": "medium",
    "auditor_notes": "secret reasoning",
}


def test_dive_record_verify(cfg, indexed):
    p, conn, snap, _sha, _tree = indexed

    run = ledger.next_unit_run(conn, p, snap, "dive", "memory")
    b = ledger.brief(conn, cfg, run)
    keys = [t["key"] for t in b["targets"]]
    # Highest-priority file first: all of parser.c's functions, none of util.c.
    assert keys == ["src/parser.c::check_len", "src/parser.c::parse", "src/parser.c::parse@2"]
    assert b["lens"]["name"] == "memory"
    assert b["dossiers"] == {"parsing": str(cfg.dossier_path("demo", "parsing"))}

    # Leased: the next dive moves on to the other file.
    run2 = ledger.next_unit_run(conn, p, snap, "dive", "memory")
    assert [t["key"] for t in ledger.brief(conn, cfg, run2)["targets"]] == ["src/util.c::helper"]

    rep = ledger.record(conn, cfg, run, audit(
        run,
        [("src/parser.c::check_len", "clean"), ("src/parser.c::parse@2", "hypotheses")],
        [HYP],
        [{"area": "parsing", "text": "check_len bounds len < 64."}],
    ))
    assert rep.covered == 2
    assert rep.missing == ["src/parser.c::parse"]
    assert rep.findings == ["parse-reads-buf-0-when-len-is-0"]
    assert "check_len bounds" in cfg.dossier_path("demo", "parsing").read_text()
    assert cfg.run_record_path("demo", run).exists()

    # The finding's location maps to the enclosing function unit.
    unit = conn.execute(
        "SELECT u.key FROM finding_locations l JOIN units u ON u.id = l.unit_id"
    ).fetchone()[0]
    assert unit == "src/parser.c::parse@2"

    # Unreported target is still open; abandon run2 and the queue offers both.
    ledger.abandon(conn, run2)
    run3 = ledger.next_unit_run(conn, p, snap, "dive", "memory")
    assert [t["key"] for t in ledger.brief(conn, cfg, run3)["targets"]] == ["src/parser.c::parse"]

    # Verify brief is blind to confidence and auditor notes.
    v = ledger.next_verify_run(conn, p)
    vb = ledger.brief(conn, cfg, v)
    assert "secret reasoning" not in json.dumps(vb)
    assert "confidence" not in vb["finding"]
    assert vb["finding"]["slug"] == "parse-reads-buf-0-when-len-is-0"
    assert ledger.next_verify_run(conn, p) is None  # leased

    rep = ledger.record(conn, cfg, v, {
        "run_id": v, "model": "test-model", "verdict": "verified",
        "reasoning": "buf[0] read with len 0", "property": "P6", "attacker": "A2",
        "cwe": "CWE-125",
    })
    assert rep.verdict == "verified"
    status, cwe = conn.execute("SELECT status, cwe FROM findings").fetchone()
    assert (status, cwe) == ("verified", "CWE-125")

    assert ledger.set_finding_status(conn, rep.findings[0], "exported") == ("verified", "exported")
    with pytest.raises(ledger.LedgerError):
        ledger.set_finding_status(conn, rep.findings[0], "hypothesis")


def test_record_rejects_bad_results(cfg, indexed):
    p, conn, snap, _sha, _tree = indexed
    run = ledger.next_unit_run(conn, p, snap, "dive", "memory")
    with pytest.raises(ledger.LedgerError, match="not a target"):
        ledger.record(conn, cfg, run, audit(run, [("src/util.c::helper", "clean")]))
    with pytest.raises(ledger.LedgerError, match="unknown unit"):
        ledger.record(conn, cfg, run, audit(run, [("nope", "clean")]))
    with pytest.raises(ledger.LedgerError, match="schema"):
        ledger.record(conn, cfg, run, {"run_id": run})
    with pytest.raises(ledger.LedgerError, match="unknown area"):
        ledger.record(conn, cfg, run, audit(run, [], dossier=[{"area": "x", "text": "t"}]))
    # Nothing was applied by the failed attempts.
    assert conn.execute("SELECT count(*) FROM coverage").fetchone()[0] == 0
    assert ledger.get_run(conn, run)["status"] == "started"

    ledger.record(conn, cfg, run, audit(run, []))
    v_missing = {"run_id": 0, "model": "m", "verdict": "verified", "reasoning": "r"}
    with pytest.raises(ledger.LedgerError):
        ledger.record(conn, cfg, run, audit(run, []))  # already recorded
    from security_dive.schemas import VerifyResult
    with pytest.raises(ValueError):
        VerifyResult.model_validate(v_missing)


def test_changed_function_loses_coverage(cfg, indexed, upstream):
    p, conn, snap, _sha, _tree = indexed
    run = ledger.next_unit_run(conn, p, snap, "sweep", "memory")
    targets = [t["key"] for t in ledger.brief(conn, cfg, run)["targets"]]
    assert len(targets) == 4  # a sweep takes every uncovered function
    ledger.record(conn, cfg, run, audit(run, [(k, "clean") for k in targets]))
    assert ledger.next_unit_run(conn, p, snap, "sweep", "memory") is None

    # Change only util.c upstream, re-index the new commit.
    (upstream / "src" / "util.c").write_text("int helper(void)\n{\n    return 2;\n}\n")
    git(upstream, "-c", "user.name=t", "-c", "user.email=t@example.com",
        "commit", "-q", "-am", "change helper")
    repo.ensure_mirror(cfg, p)
    sha2 = repo.resolve(cfg, p, "main")
    snap2 = ledger.snapshot_id(conn, p.name, sha2, "main")
    ledger.index_units(conn, p.name, snap2, extract_tree(p, repo.snapshot(cfg, p, sha2)))

    run2 = ledger.next_unit_run(conn, p, snap2, "sweep", "memory")
    assert [t["key"] for t in ledger.brief(conn, cfg, run2)["targets"]] == ["src/util.c::helper"]

    rows = {r["area"]: r for r in ledger.coverage_by_area(conn, snap2, None)}
    assert rows["parsing"]["swept"] == 3 and rows["misc"]["swept"] == 0

    # Editing the lens makes it a new version: everything is uncovered under it.
    (p.lenses_dir / "memory.md").write_text("Look harder for memory bugs.\n")
    ledger.abandon(conn, run2)
    run3 = ledger.next_unit_run(conn, p, snap2, "sweep", "memory")
    assert len(ledger.brief(conn, cfg, run3)["targets"]) == 4
