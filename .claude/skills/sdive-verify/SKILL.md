---
name: sdive-verify
description: Run blind, adversarial verification of security-dive vulnerability hypotheses. Each run gives one hypothesis (claim and locations only) to the sdive-verifier subagent, which tries to refute it against the source, and records the verdict. Invoke as /sdive-verify <project> [N|all] [--ledger X]. Use after dives or sweeps have raised hypotheses.
argument-hint: "<project> [N|all] [--ledger main]"
allowed-tools: Bash, Read, Agent, SendMessage
---

You orchestrate **verify runs**. The verification happens in the
`sdive-verifier` subagent, which must stay blind: it sees only what `sdive`
puts in the brief.

## Arguments

`<project>`; a count `N` (default 1) or `all`; `--ledger` (default `main`).

## Before the loop: interrupted runs

A session stopped mid-run leaves runs `started`; their targets stay leased
(skipped by `next`) for 12 hours. Unless the user says another session is
working on this ledger right now, tidy them first:
`uv run sdive --ledger <ledger> runs <project> --status started --limit 0`.
For each one of this skill's kind, run `uv run sdive --ledger <ledger> record <id>`
(the agent may have finished writing its result); if that says there is no
result file, `uv run sdive --ledger <ledger> abandon <id>`.

## Loop

1. `uv run sdive --ledger <ledger> next <project> --kind verify`
   - Exit status 3: no unverified hypotheses left; stop.
   - Other failure: report and stop.
2. Dispatch the agent named in `agent` with exactly the prompt
   `Brief: <brief_path>` — nothing more. In particular, never tell the verifier
   who raised the hypothesis, the auditor's confidence or notes, or your opinion.
3. Run `record_command`. On a validation error, SendMessage the error to the same
   agent to fix `result_path`, then record again (at most two rounds); if it still
   fails, `uv run sdive --ledger <ledger> abandon <run_id>`.
4. Print one line: finding slug → verdict, and the decisive reason in a phrase.

Verify runs are independent; you may keep up to 3 in flight if the user asked
for speed.

## Finish

`uv run sdive --ledger <ledger> findings <project>`, then summarize the verdicts:
verified (with property/attacker), rejected, inconclusive.

## Invariants

- Never write result files or change a verdict yourself; status changes after
  verification go through `uv run sdive finding set` at the user's request.
- Never read `analysis/truth/` or any zepsec analysis directory.
