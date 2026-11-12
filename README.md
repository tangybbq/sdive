# security-dive

Proactive, incremental security analysis of MCUboot and Zephyr, run as Claude
Code skills, with a SQLite ledger tracking what has been examined. See
`PLAN.md` for the design.

```sh
direnv allow
uv sync
uv run sdive init                 # analysis/ (private nested repo), work/, the DB
uv run sdive mirror mcuboot       # private bare mirror under work/mirrors/
uv run sdive units mcuboot        # snapshot main, index files + functions by area
uv run sdive coverage mcuboot     # per-area swept/dived coverage
```

Analysis runs interactively as Claude Code skills (start a session with the
model you want, e.g. Mythos):

```
uv run sdive todo mcuboot                   # runs left per lens: pick a batch size
/sdive-sweep mcuboot memory-safety 2        # 2 sweep runs (a few areas each)
/sdive-dive mcuboot 10                      # 10 deep-dive runs (holistic lens)
/sdive-verify mcuboot all                   # blind verification of hypotheses
/sdive-bench mcuboot vanessa --rev 511dc9e2 # calibration round in a fresh ledger
```

The count is the stopping point. Coverage is recorded per run, so the next
session continues where the last one stopped, as long as the code and the lens
are unchanged: a changed function, or an edited lens file, puts that work back
in the queue (agent prompt edits do not).

The loop underneath:

```sh
uv run sdive next mcuboot --kind dive --lens <lens>   # starts a run, prints the brief JSON
#   ... subagent writes analysis/staging/run-<id>.json ...
uv run sdive record <id>                              # validate + apply to the ledger
uv run sdive next mcuboot --kind verify               # blind verification of a hypothesis
uv run sdive findings mcuboot
uv run sdive --ledger <round> bench judge mcuboot vanessa <item> <slug>...  # score a round
uv run sdive carry mcuboot --from <round>          # re-queue a round's verified findings at main
uv run sdive upstream mcuboot                         # defects noted in reference trees
uv run sdive schema audit|verify                      # the result JSON schemas
```

`next` exits with status 3 when the queue is empty. `abandon <id>` releases a
run's targets; unrecorded runs also expire after 12 hours.

Project scope, areas and reference trees (submodules exported read-only for API
lookup, never audited): `projects/<name>/project.toml`. Lenses:
`projects/<name>/lenses/<lens>.md` (versioned by content hash).

Development: `uv run pytest`, `uvx ruff check src tests`.
