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

The analysis loop (normally driven by a skill):

```sh
uv run sdive next mcuboot --kind dive --lens <lens>   # starts a run, prints the brief JSON
#   ... subagent writes analysis/staging/run-<id>.json ...
uv run sdive record <id>                              # validate + apply to the ledger
uv run sdive next mcuboot --kind verify               # blind verification of a hypothesis
uv run sdive findings mcuboot
uv run sdive upstream mcuboot                         # defects noted in reference trees
uv run sdive schema audit|verify                      # the result JSON schemas
```

`next` exits with status 3 when the queue is empty. `abandon <id>` releases a
run's targets; unrecorded runs also expire after 12 hours.

Project scope, areas and reference trees (submodules exported read-only for API
lookup, never audited): `projects/<name>/project.toml`. Lenses:
`projects/<name>/lenses/<lens>.md` (versioned by content hash).

Development: `uv run pytest`, `uvx ruff check src tests`.
