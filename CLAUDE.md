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

## Dev

- Python via `uv` only (`uv run`, `uv add`); never pip.
- Tests: `uv run pytest`.
