import json
import sys
from pathlib import Path

from security_dive import blind, launch


def test_choose_auto_order():
    runs = {"memory-safety": 0, "authenticity": 3}.get
    order = ["memory-safety", "authenticity"]
    assert launch.choose(None, None, 2, runs, order).kind == "verify"
    p = launch.choose(None, None, 0, runs, order)
    assert (p.kind, p.lens) == ("sweep", "authenticity")
    assert launch.choose(None, None, 0, lambda n: 0, order).kind == "dive"
    assert launch.choose("verify", None, 0, runs, order) is None
    assert launch.choose("sweep", "memory-safety", 0, runs, order) is None
    assert launch.choose("dive", None, 5, runs, order).kind == "dive"


def test_invocation_and_command(tmp_path):
    sweep = launch.Plan("sweep", "authenticity", "")
    assert launch.invocation(sweep, "mcuboot", "main", None, 40, 2) == (
        "/sdive-sweep mcuboot authenticity --minutes 40 --parallel 2")
    dive = launch.Plan("dive", None, "")
    assert launch.invocation(dive, "mcuboot", "bench-x", 3, None, 1) == (
        "/sdive-dive mcuboot 3 --ledger bench-x")
    argv = launch.command("/sdive-dive mcuboot 1", "m", True, tmp_path / "staging")
    assert argv[:3] == ["claude", "--model", "m"] and argv[-1] == "/sdive-dive mcuboot 1"
    assert f"Write(/{(tmp_path / 'staging').resolve()}/**)" in argv
    assert "acceptEdits" not in argv and "--permission-mode" not in argv
    deny = argv.index("--disallowedTools")
    assert argv[deny + 1:deny + 4] == blind.deny_rules()
    assert argv.index("--allowedTools") == deny + 4
    assert launch.command("x", "m", False, tmp_path) == ["claude", "--model", "m", "x"]


def test_child_env_strips_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert "ANTHROPIC_API_KEY" not in launch.child_env(False)
    assert launch.child_env(True)["ANTHROPIC_API_KEY"] == "sk-test"


def test_run_streams_and_saves(tmp_path):
    events = [
        {"type": "system", "subtype": "init"},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": "uv run sdive next x"}}]}},
        {"type": "assistant", "parent_tool_use_id": "t1", "message": {"content": [
            {"type": "text", "text": "subagent chatter"}]}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "done"}]}},
        {"type": "result", "subtype": "success", "result": "done", "total_cost_usd": 1.5,
         "duration_ms": 90000, "num_turns": 4},
    ]
    script = tmp_path / "fake.py"
    script.write_text("import sys\nfor l in sys.argv[1:]: print(l)\n")
    out = tmp_path / "out.txt"
    with out.open("w") as f:
        st = launch.run([sys.executable, str(script), *map(json.dumps, events)], {},
                        tmp_path, tmp_path / "sessions", {"prompt": "p"}, out=f)
    assert st == 0
    text = out.read_text()
    assert "→ Bash: uv run sdive next x" in text and "subagent chatter" not in text
    assert text.count("done") == 1
    assert "1.5 min" in text and "$1.50" in text
    saved = json.loads(next(Path(tmp_path / "sessions").glob("*.json")).read_text())
    assert saved["prompt"] == "p" and saved["result"]["total_cost_usd"] == 1.5
    assert "result" not in saved["result"]
