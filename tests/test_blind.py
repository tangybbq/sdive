import json
import subprocess
import sys

import pytest

from security_dive import blind


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A fake home with a zepsec checkout, and a project with ground truth."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    proj = tmp_path / "proj"
    for d in ("analysis/truth/mcuboot", "analysis/staging", "work/snapshots/s"):
        (proj / d).mkdir(parents=True)
    for d in ("ai/zepsec/analysis/x", "ai/zepsec-prod/analysis", "ai/zepsec/src"):
        (home / d).mkdir(parents=True)
    (home / "ai/zepsec/threat-model.md").write_text("")
    protected = ((str(proj / "analysis/truth"), True), ("~/ai/zepsec*/analysis", True),
                 ("~/ai/zepsec/threat-model.md", False))
    monkeypatch.setattr(blind, "PROTECTED", protected)
    return proj, home


def ev(tool, agent="sdive-auditor", cwd=None, **args):
    e = {"tool_name": tool, "tool_input": args, "cwd": cwd or "/"}
    if agent:
        e["agent_type"] = agent
    return e


def test_read(tree):
    proj, home = tree
    assert blind.decide(ev("Read", file_path=f"{proj}/analysis/truth/mcuboot/t.json"))
    assert blind.decide(ev("Read", file_path=f"{home}/ai/zepsec-prod/analysis/a.md"))
    assert blind.decide(ev("Read", file_path="~/ai/zepsec/threat-model.md"))
    assert blind.decide(ev("Read", file_path="../analysis/truth/x", cwd=str(proj / "work")))
    assert not blind.decide(ev("Read", file_path=f"{proj}/work/snapshots/s/a.c"))
    assert not blind.decide(ev("Read", file_path=f"{home}/ai/zepsec/src/a.py"))
    assert not blind.decide(ev("Read", file_path=f"{proj}/analysis/staging/r.json"))


def test_symlink_into_truth(tree):
    proj, _ = tree
    link = proj / "work/snapshots/s/sneaky"
    link.symlink_to(proj / "analysis/truth")
    assert blind.decide(ev("Read", file_path=f"{link}/mcuboot/t.json"))
    assert blind.decide(ev("Grep", path=str(link)))


def test_search_roots(tree):
    proj, home = tree
    snap = str(proj / "work/snapshots/s")
    assert not blind.decide(ev("Grep", path=snap, pattern="memcpy"))
    assert not blind.decide(ev("Glob", path=snap, pattern="**/*.c"))
    assert not blind.decide(ev("Glob", pattern="**/*.c", cwd=snap))
    # Roots that contain protected trees, or sit inside one.
    assert blind.decide(ev("Grep", path=str(proj), pattern="x"))
    assert blind.decide(ev("Grep", pattern="x", cwd=str(proj)))      # no path: cwd
    assert blind.decide(ev("Grep", path=f"{proj}/analysis", pattern="x"))
    assert blind.decide(ev("Grep", path=f"{home}/ai", pattern="x"))
    assert blind.decide(ev("Grep", path=f"{home}/ai/zepsec", pattern="x"))
    assert blind.decide(ev("Grep", path="/", pattern="x"))
    assert blind.decide(ev("Glob", path=f"{proj}/analysis/truth/mcuboot", pattern="*"))
    # Patterns that move the root.
    assert blind.decide(ev("Glob", path=snap, pattern=f"{home}/ai/zepsec/analysis/**"))
    assert blind.decide(ev("Glob", path=snap, pattern="../../../analysis/truth/**"))
    assert blind.decide(ev("Glob", path=snap, pattern="~/ai/*/analysis/*"))


def test_other_callers_untouched(tree):
    proj, _ = tree
    truth = f"{proj}/analysis/truth/mcuboot/t.json"
    assert not blind.decide(ev("Read", agent=None, file_path=truth))
    assert not blind.decide(ev("Read", agent="Explore", file_path=truth))
    assert not blind.decide(ev("Grep", agent=None, path=str(proj)))
    assert not blind.decide(ev("Write", file_path=truth))
    assert blind.decide(ev("Read", agent="sdive-verifier", file_path=truth))


def test_deny_rules():
    rules = blind.deny_rules()
    assert f"Read(/{blind.PROJECT}/analysis/truth/**)" in rules
    assert "Read(~/ai/zepsec*/analysis/**)" in rules
    assert "Read(~/ai/zepsec/threat-model.md)" in rules


def test_hook_process():
    """The file runs standalone, as the hook invokes it."""
    def run(stdin):
        return subprocess.run([sys.executable, "-I", blind.__file__], input=stdin,
                              capture_output=True, text=True)
    truth = str(blind.PROJECT / "analysis/truth/x.json")
    r = run(json.dumps(ev("Read", file_path=truth)))
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert r.returncode == 0 and out["permissionDecision"] == "deny"
    r = run(json.dumps(ev("Read", agent=None, file_path=truth)))
    assert r.returncode == 0 and r.stdout == ""
    assert run("not json").returncode == 2
