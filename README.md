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

Analysis runs as Claude Code skills. `sdive run` picks the next work and
launches `claude` on it headless (default model `claude-mythos-5-2`, or
`--model`/`SDIVE_MODEL`), streaming progress and saving the session log and
its reported cost under `analysis/sessions/`:

```sh
uv run sdive run mcuboot --minutes 40          # verify pending, else next sweep lens, else dives
uv run sdive run mcuboot dive --runs 1         # one dive
uv run sdive run mcuboot sweep authenticity --minutes 30 --parallel 2
uv run sdive run mcuboot --dry-run             # show the claude command only
uv run sdive run mcuboot -i                    # same, but an interactive session
```

Or type the skills yourself in a Claude Code session:

```
uv run sdive todo mcuboot --minutes 40      # runs and agent-minutes left per lens
/sdive-sweep mcuboot memory-safety 2        # 2 sweep runs (a few areas each)
/sdive-dive mcuboot --minutes 40            # as many dives as fit in ~40 agent-minutes
/sdive-dive mcuboot 10 --parallel 3         # 10 dives, 3 at a time
/sdive-verify mcuboot all                   # blind verification of hypotheses
/sdive-bench mcuboot vanessa --rev 511dc9e2 # calibration round in a fresh ledger
```

Agent-minutes are estimated from the median recorded run time of each kind
and track cost; parallel runs save wall-clock time but cost the same. The
count is the stopping point. Coverage is recorded per run, so the next
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
