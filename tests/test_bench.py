import json

from security_dive import bench, ledger, repo
from security_dive.db import connect
from security_dive.units import extract_tree


def _corpus(tmp_path):
    c = tmp_path / "corpus"
    items = {
        # Validated bug at parser.c:13 (inside parse@2).
        "001-parse-oob": ({"short_id": "001", "title": "parse OOB", "site": "src/parser.c:13",
                           "scanned_commit": "abc"},
                          {"is_vulnerability": "yes", "cwe": "CWE-125"}),
        # Refuted claim, file only, partial path.
        "002-helper": ({"short_id": "002", "title": "helper issue"},
                       {"is_vulnerability": "no", "affected_components": "['util.c']"}),
        # Out of scope (port not indexed).
        "003-port": ({"short_id": "003", "title": "port bug", "site": "boot/port/x.c:5"},
                     {"is_vulnerability": "yes"}),
        # Own finding: result.json only.
        "own-finding": ({}, {"is_vulnerability": "unclear",
                             "affected_components": ["src/parser.c"]}),
    }
    for name, (disc, res) in items.items():
        d = c / name
        d.mkdir(parents=True)
        if disc:
            (d / "disclosure.json").write_text(json.dumps(disc))
        (d / "result.json").write_text(json.dumps(res))
    # 003's agent verdict says "yes"; a human override refutes it and wins.
    (c / "003-port" / "override.json").write_text(json.dumps(
        {"is_vulnerability": "no", "disposition": "refuted"}))
    return c


def test_import_and_report(tmp_path, cfg):
    data = bench.save_truth(cfg, "demo", "t", [_corpus(tmp_path)])
    by_id = {i["id"]: i for i in data["items"]}
    assert by_id["001"]["verdict"] == "tp" and by_id["001"]["site"] == {
        "path": "src/parser.c", "line": 13}
    assert by_id["002"]["files"] == ["util.c"] and by_id["002"]["verdict"] == "fp"
    assert by_id["own-finding"]["verdict"] == "unclear"
    assert by_id["003"]["verdict"] == "fp" and by_id["003"]["overridden"]
    assert not by_id["001"]["overridden"]
    assert bench.truth_path(cfg, "demo", "t").is_relative_to(cfg.analysis / "truth")

    b = cfg.with_ledger("b1")
    p = b.project("demo")
    repo.ensure_mirror(b, p)
    sha = repo.resolve(b, p, "main")
    conn = connect(b.db_path)
    snap = ledger.snapshot_id(conn, "demo", sha)
    ledger.index_units(conn, "demo", snap, extract_tree(p, repo.snapshot(b, p, sha)))

    run = ledger.next_unit_run(conn, p, snap, "dive", "memory")
    hyp = {"title": "buf[0] read with len 0", "claim": "c", "confidence": "high",
           "locations": [{"path": "src/parser.c", "start_line": 12}]}
    novel = {"title": "something new", "claim": "c", "confidence": "low",
             "locations": [{"path": "src/parser.c", "start_line": 3}]}
    ledger.record(conn, b, run, {
        "run_id": run, "model": "m", "summary": "s",
        "units": [{"key": "src/parser.c::parse@2", "status": "hypotheses"}],
        "hypotheses": [hyp, novel]})
    v = ledger.next_verify_run(conn, p)
    ledger.record(conn, b, v, {"run_id": v, "model": "m", "verdict": "verified",
                               "reasoning": "r", "property": "P6", "attacker": "A2"})

    r = bench.report(conn, "demo", snap, data)
    rows = {row["id"]: row for row in r["items"]}
    assert rows["001"]["examined"] == "yes"
    assert rows["001"]["matches"][0] == {
        "slug": "buf-0-read-with-len-0", "status": "verified", "strength": "unit"}
    assert rows["001"]["hits"] is None
    assert rows["002"]["in_scope"] and rows["002"]["examined"] == "0/1"
    assert not rows["003"]["in_scope"]
    # Unjudged: a unit-level candidate is not a hit, only awaiting judgement.
    assert r["summary"]["tp"] == {"in_scope": 1, "raised": 0, "confirmed": 0, "rejected": 0,
                                  "pending": 1}
    assert r["out_of_scope"] == 1
    unmatched = {f["slug"]: f["candidate_for"] for f in r["unmatched_findings"]}
    # "something new" is also in parse@2's file but outside the function, so
    # it's not a candidate for 001.
    assert unmatched == {"buf-0-read-with-len-0": ["001"], "something-new": []}

    bench.judge(b, "t", "001", ["buf-0-read-with-len-0"], note="same bug")
    bench.judge(b, "t", "002", [])
    assert bench.adjudication_path(b).parent == b.ledger_dir
    r = bench.report(conn, "demo", snap, data, bench.load_judgments(b, "t"))
    rows = {row["id"]: row for row in r["items"]}
    assert rows["001"]["hits"] == [{"slug": "buf-0-read-with-len-0", "status": "verified"}]
    assert rows["001"]["judge_note"] == "same bug" and rows["002"]["hits"] == []
    assert r["summary"]["tp"] == {"in_scope": 1, "raised": 1, "confirmed": 1, "rejected": 0,
                                  "pending": 0}
    assert r["summary"]["fp"]["raised"] == 0 and r["summary"]["fp"]["pending"] == 0
    assert [f["slug"] for f in r["unmatched_findings"]] == ["something-new"]

    # A judgement can name a finding located elsewhere; clearing restores pending.
    bench.judge(b, "t", "002", ["something-new"])
    bench.judge(b, "t", "001", None)
    r = bench.report(conn, "demo", snap, data, bench.load_judgments(b, "t"))
    assert r["summary"]["fp"]["raised"] == 1 and r["summary"]["fp"]["confirmed"] == 0
    assert r["summary"]["tp"]["pending"] == 1
    assert bench.load_judgments(cfg, "t") == {}  # main ledger is separate
