---
name: sdive-sweep
description: Run security-dive sweep runs — one sdive-auditor pass over all uncovered in-scope code (or one area) through a single focused lens — and record coverage and hypotheses. Invoke as /sdive-sweep <project> <lens|all> [--area A] [--rev R] [--ledger X]. Use when the user wants a broad pass over a code base for one class of vulnerability.
argument-hint: "<project> <lens|all> [--area A] [--rev R] [--ledger main]"
allowed-tools: Bash, Read, Agent, SendMessage
---

You orchestrate **sweep runs**: whole-code-base passes through one lens each.
The analysis happens in the `sdive-auditor` subagent.

## Arguments

`<project>`; `<lens>` or `all` (every lens in `projects/<project>/lenses/`
except `holistic`, which is for dives — list them with
`uv run sdive lenses <project>`); optional `--area`, `--rev`; `--ledger`
(default `main`). Every command is `uv run sdive --ledger <ledger> ...`.

## For each lens

1. `uv run sdive --ledger <ledger> next <project> --kind sweep --lens <lens> [--area A] [--rev R]`
   - Exit status 3: nothing left to sweep under this lens; go to the next lens.
   - Other failure: report and stop.
2. Dispatch the agent named in `agent` with exactly the prompt
   `Brief: <brief_path>` — nothing more.
3. Run `record_command`. On a validation error, SendMessage the error to the same
   agent to fix `result_path`, then record again (at most two rounds); if it still
   fails, `uv run sdive --ledger <ledger> abandon <run_id>`.
4. Print one line: lens, units covered/partial, hypothesis titles.

Sweeps over different lenses are independent: with `all`, you may run up to 3
lenses in parallel if the user asked for speed.

## Finish

`uv run sdive --ledger <ledger> coverage <project>`, then a short summary and,
if there are new hypotheses, suggest `/sdive-verify`.

## Invariants

- Never write result files, lenses, the threat model or dossiers yourself.
- Never read `analysis/truth/` or any zepsec analysis directory, and never pass
  their contents to an agent.
