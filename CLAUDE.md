# CLAUDE.md — security-dive

Proactive security analysis of MCUboot, then Zephyr. **`PLAN.md` is the design
and roadmap** — read it before structural changes.

## Shape

- `sdive` (`src/security_dive/`) is the deterministic CLI: mirrors, snapshots,
  units, the SQLite ledger, the queue, validated ingestion, reports. **It makes
  no LLM/API calls.**
- Analysis runs as Claude Code skills/subagents in `.claude/`, interactively.
  Agents write JSON to staging; only `sdive record` writes the ledger.
- Config: `config.toml` (per-project paths/repos).

## Invariants

- **Never write to the user's source checkouts** (`~/ai/mcuboot`,
  `~/linaro/mcuboot`, `~/zephyrproject/zephyr`). Use `work/mirrors/` and
  read-only snapshots under `work/snapshots/`. When running `jj` against a user
  repo for reading, pass `--ignore-working-copy`.
- **`analysis/` is private** (live, embargoed vulnerabilities): gitignored here,
  never published, never quoted in commit messages, PRs or issues.
- **Change findings follow the disclosure policy in `PLAN.md`**: comment on an
  unmerged PR (show the user the draft before posting); merged but unreleased →
  ordinary fix, no GHSA/CVE; released → GHSA via zepsec.
- Every verdict names the threat-model property and attacker class
  (`../zepsec/threat-model.md` for MCUboot).

## Commits

Plain git, single developer. **Commit as needed**: once a change is built and
its tests pass, commit it without waiting to be asked. Reviews happen on
commits, not on the dirty tree, so keep commits coherent and well described.
Amending is fine for work that hasn't been pushed. Identity is set repo-local
(linaro.org address); message format and `Assisted-by:` trailer per the global
instructions.

## Dev

- Python via `uv` only (`uv run`, `uv add`); never pip.
- Tests: `uv run pytest`. Lint: `uvx ruff check src tests`.
- Module map: `config.py` (config + project scope/areas), `repo.py` (mirror,
  snapshots), `units.py` (tree-sitter extraction), `db.py` (schema, append-only
  migrations), `schemas.py` (agent result models), `ledger.py` (queue, record,
  reports), `cli.py`.
