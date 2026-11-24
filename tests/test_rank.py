import json

import pytest

from security_dive import rank
from security_dive.units import extract_source

from .test_flow import indexed  # noqa: F401  (fixture)


def test_signals_and_bonus():
    src = """\
int l2cap_recv(struct net_buf *buf)
{
    struct hdr *h = net_buf_pull_mem(buf, sizeof(*h));
    uint16_t len = sys_le16_to_cpu(h->len);
    __ASSERT(len <= buf->len, "bad len");
    memcpy(dst, buf->data, len - 4);
    net_buf_unref(buf);
    return 0;
}
"""
    sig = rank.signals(src, "l2cap_recv")
    assert sig == {"parse": 1, "copy": 1, "len_arith": 1, "assert_check": 1, "lifetime": 1,
                   "handler": 1}
    assert rank.signal_bonus(sig) == pytest.approx(0.15 + 0.1 + 0.1 + 0.15 + 0.05 + 0.2)
    assert rank.signal_bonus({"parse": 100, "copy": 100, "syscall": 100,
                              "len_arith": 100}) == rank.MAX_SIGNAL_BONUS
    assert rank.score(5, {}, built=False, reach=0) == 5 + rank.UNBUILT - 2.0
    assert rank.score(4, {}, built=None, reach=3) == 5.5


def test_units_carry_signals():
    src = b"int z_vrfy_x(int *p) { K_OOPS(K_SYSCALL_MEMORY_READ(p, 4)); }\n"
    units = extract_source("a.c", src,
                           "a", 4)
    fn = [u for u in units if u.kind == "function"][0]
    assert json.loads(fn.signals) == {"syscall": 3, "handler": 1}  # name included


def test_rank_brief_record_rescore(cfg, indexed):  # noqa: F811
    p, conn, snap, _sha, _tree = indexed
    b = rank.write_brief(conn, cfg, p, snap, max_functions=3)
    assert [f["path"] for f in b["files"]] == ["src/parser.c"]
    keys = [fn["key"] for fn in b["files"][0]["functions"]]
    assert keys == ["src/parser.c::check_len", "src/parser.c::parse", "src/parser.c::parse@2"]
    # Its functions are leased: the next brief takes the next file.
    b2 = rank.write_brief(conn, cfg, p, snap)
    assert [f["path"] for f in b2["files"]] == ["src/util.c"]
    res = {"brief_id": b["brief_id"], "model": "m", "units": [
        {"key": k, "reach": r, "attacker": "A1" if r else None, "reason": "x"}
        for k, r in zip(keys, (0, 3, 3), strict=True)]}
    with open(b["result_path"], "w") as f:
        json.dump({**res, "units": res["units"][:2]}, f)
    with pytest.raises(rank.RankError, match="no judgement"):
        rank.record(conn, cfg, b["brief_id"])
    res["units"][0]["reason"] = "y" * 250  # Haiku overshoots; recording shortens it
    with open(b["result_path"], "w") as f:
        json.dump(res, f)
    assert rank.record(conn, cfg, b["brief_id"]) == (3, 1)
    assert len(conn.execute("SELECT reason FROM unit_reach ORDER BY id").fetchone()[0]) == 200
    scores = dict(conn.execute(
        "SELECT u.key, uv.score FROM unit_versions uv JOIN units u ON u.id = uv.unit_id "
        "WHERE uv.snapshot_id = ? AND u.kind = 'function'", (snap,)).fetchall())
    assert scores["src/parser.c::check_len"] == 5 - 2.0
    assert scores["src/parser.c::parse"] == pytest.approx(5 + 0.2 + 1.5)
    assert rank.unranked(conn, snap)[0]["key"] == "src/util.c::helper"
    # The recorded brief is timed for `sdive todo`.
    from security_dive import ledger
    assert conn.execute("SELECT functions FROM rank_briefs").fetchone()[0] == 3
    assert ledger.run_minutes([conn], p.name)["rank"][1] == 1


def test_rank_by_area(cfg, indexed):  # noqa: F811
    p, conn, snap, _sha, _tree = indexed
    assert {r["area"] for r in rank.unranked(conn, snap, area="misc")} == {"misc"}
    assert rank.unranked(conn, snap, min_priority=4, area="misc") == []
    # parser.c outranks util.c, but the area brief skips it.
    b = rank.write_brief(conn, cfg, p, snap, area="misc")
    assert [f["path"] for f in b["files"]] == ["src/util.c"]
    assert rank.write_brief(conn, cfg, p, snap, area="misc") is None


def test_batches_whole_files():
    rows = [{"path": p} for p in ["a", "a", "b", "c", "c", "c", "d"]]
    out = [[(path, len(fns)) for path, fns, _ in b] for b in rank.batches(rows, 3)]
    # Without a size budget a file never splits; one larger than the limit
    # gets a brief of its own.
    assert out == [[("a", 2), ("b", 1)], [("c", 3)], [("d", 1)]]
    assert [[p for p, _, _ in b] for b in rank.batches(rows, 2)] == [["a"], ["b"], ["c"], ["d"]]


def test_batches_context_budget(tmp_path):
    # Every line is 100 bytes, so sizes are easy to reason about.
    line = "x" * 99 + "\n"
    (tmp_path / "big.c").write_text(line * 1000)     # 100 KB: over budget alone
    (tmp_path / "s1.c").write_text(line * 300)       # 30 KB
    (tmp_path / "s2.c").write_text(line * 300)
    size = rank.file_sizer(tmp_path)
    assert size("s1.c") == 30_000 and size("s1.c", 1, 10) == 1000 and size("nope.c") == 0
    big = [{"path": "big.c", "start_line": s, "end_line": s + 99} for s in range(1, 1000, 100)]
    small = [{"path": f, "start_line": 1, "end_line": 300} for f in ("s1.c", "s2.c")]
    out = list(rank.batches(big + small, size=size, max_tokens=60_000))
    # 60K budget, 18K base: big.c splits into line ranges (100-line head plus
    # 330/function + 0.8/byte), each its own brief; the two 30 KB files
    # (24.3K each) do not fit one brief together.
    chunks = [b for b in out if b[0][0] == "big.c"]
    assert all(len(b) == 1 and b[0][2] for b in chunks)
    assert sum(len(b[0][1]) for b in chunks) == 10
    for b in chunks:
        path, fns, (lo, hi) = b[0]
        assert (lo, hi) == (fns[0]["start_line"], fns[-1]["end_line"])
        assert rank.RANK_BASE_TOKENS + rank.estimate_tokens(
            len(fns), size(path, 1, 100) + size(path, lo, hi)) <= 60_000
    assert [[(p, ln) for p, _, ln in b] for b in out if b[0][0] != "big.c"] == [
        [("s1.c", None)], [("s2.c", None)]]
    # With the default budget the small files share a brief.
    assert [[p for p, _, _ in b] for b in rank.batches(small, size=size)] == [["s1.c", "s2.c"]]


def test_reach_carries_to_unchanged_functions(cfg, indexed, upstream):  # noqa: F811
    from security_dive import ledger, repo
    from security_dive.units import extract_tree

    from .conftest import git
    p, conn, snap, _sha, _tree = indexed
    b = rank.write_brief(conn, cfg, p, snap)
    keys = [fn["key"] for f in b["files"] for fn in f["functions"]]
    assert "src/util.c::helper" in keys
    with open(b["result_path"], "w") as f:
        json.dump({"brief_id": b["brief_id"], "model": "m", "units": [
            {"key": k, "reach": 3, "attacker": "A1", "reason": "x"} for k in keys]}, f)
    rank.record(conn, cfg, b["brief_id"])

    # Change only util.c upstream: helper needs ranking again, parser.c doesn't.
    (upstream / "src" / "util.c").write_text("int helper(void)\n{\n    return 2;\n}\n")
    git(upstream, "-c", "user.name=t", "-c", "user.email=t@example.com",
        "commit", "-q", "-am", "change helper")
    repo.ensure_mirror(cfg, p)
    sha2 = repo.resolve(cfg, p, "main")
    snap2 = ledger.snapshot_id(conn, p.name, sha2, "main")
    tree2 = repo.snapshot(cfg, p, sha2)
    assert ledger.index_units(conn, p.name, snap2, extract_tree(p, tree2)) == len(keys) - 1
    assert [r["key"] for r in rank.unranked(conn, snap2)] == ["src/util.c::helper"]
    row = conn.execute(
        "SELECT reach, carried_from FROM unit_reach r JOIN units u ON u.id = r.unit_id "
        "WHERE r.snapshot_id = ? AND u.key = 'src/parser.c::parse'", (snap2,)).fetchone()
    assert tuple(row) == (3, snap)
    # Carried reach counts in the score; re-indexing doesn't carry twice.
    s1, s2 = (conn.execute(
        "SELECT uv.score FROM unit_versions uv JOIN units u ON u.id = uv.unit_id "
        "WHERE uv.snapshot_id = ? AND u.key = 'src/parser.c::parse'", (s,)).fetchone()[0]
        for s in (snap, snap2))
    assert s1 == s2
    assert ledger.index_units(conn, p.name, snap2, extract_tree(p, tree2)) == 0


def test_rank_loop_records_and_retries(cfg, indexed):  # noqa: F811
    import io

    from security_dive import launch
    p, conn, snap, _sha, _tree = indexed
    calls = []

    def fake_agent(argv, env, cwd, log_path):
        calls.append(argv)
        prompt = argv[-1]
        if prompt.startswith("Brief: "):
            b = json.load(open(prompt.removeprefix("Brief: ")))
            keys = [fn["key"] for f in b["files"] for fn in f["functions"]]
            if "src/util.c::helper" in keys:  # first try leaves a unit out
                keys = keys[1:]
        else:
            assert "--resume" in argv and "no judgement" in prompt
            b = json.load(open(next(f for f in cfg.staging.glob("rank-*.brief.json"))))
            keys = [fn["key"] for f in b["files"] for fn in f["functions"]]
        with open(b["result_path"], "w") as f:
            json.dump({"brief_id": b["brief_id"], "model": "m", "units": [
                {"key": k, "reach": 1, "attacker": "A1", "reason": "x"} for k in keys]}, f)
        return {"session_id": "s1", "total_cost_usd": 0.01, "is_error": False}

    out = io.StringIO()
    t = launch.rank_loop(conn, cfg, p, snap, None, 1, 0, {}, agent_runner=fake_agent, out=out)
    assert t["briefs"] == 1 and t["failed"] == 0 and t["cost"] == pytest.approx(0.02)
    assert "after retry" in out.getvalue()
    assert calls[0][:4] == ["claude", "-p", "--agent", "sdive-ranker"]
    assert rank.unranked(conn, snap) == []
    assert not list(cfg.staging.glob("rank-*.brief.json"))
