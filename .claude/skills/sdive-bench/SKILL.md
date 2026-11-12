---
name: sdive-bench
description: Run a blind security-dive benchmark round — a fresh disposable ledger at a commit with known ground truth, sweeps and dives with the current lenses and agents, verification of every hypothesis, then a scored report. Invoke as /sdive-bench <project> <truth-set> --rev <commit> [--round NAME] [--dives N|all] [--sweeps all|none|<lens,...>]. Use to calibrate lenses and agent prompts before analysing current code.
argument-hint: "<project> <truth-set> --rev <commit> [--round NAME] [--dives all] [--sweeps all]"
allowed-tools: Bash, Read, Agent, SendMessage
---

A benchmark round measures the *current* lenses and agents against a commit
whose vulnerabilities are already known. It must be **blind**: neither you nor
any agent reads the ground truth until the analysis is finished. Only the final
`sdive bench report` touches it.

## Arguments

`<project>`, `<truth-set>` (e.g. `vanessa`, imported earlier with
`sdive bench import`), `--rev` (required, e.g. `511dc9e2`), `--round` (ledger
name; default `bench-<truth-set>-<YYYYMMDD>`; refuse to reuse an existing
ledger directory under `analysis/ledgers/` — rounds start clean), `--dives`
(default `all`), `--sweeps` (default `all`).

## Steps

1. **Fresh ledger:** `uv run sdive --ledger <round> units <project> <rev>` —
   snapshots and indexes the commit in the new ledger.
2. **Sweeps** (unless `none`): follow the /sdive-sweep procedure with
   `--ledger <round> --rev <rev>` for each requested lens.
3. **Dives:** follow the /sdive-dive procedure with `--ledger <round> --rev <rev>`
   and the `holistic` lens, for the requested count.
4. **Verify:** follow the /sdive-verify procedure with `--ledger <round>` and
   `all`.
5. **Score:** `uv run sdive --ledger <round> bench report <project> <truth-set> --rev <rev>`.

Steps 2–4 can take many runs. Report progress briefly after each step; if the
user stops partway, the ledger keeps everything done so far and the round can be
resumed with the same `--round`.

## Report to the user

- Recall: validated bugs in scope raised / confirmed by the verifier.
- Traps: refuted claims raised, wrongly confirmed, correctly rejected.
- Findings matching no truth item — these need human review: they may be new
  bugs (still present on `main`?) or false positives.
- For each missed validated bug: whether its code was examined (the `examined`
  column) — "not examined" is a coverage gap, "examined but not raised" is a
  lens/prompt gap.
- The model(s) used (`uv run sdive --ledger <round> runs <project>`).

Do not edit lenses or agent prompts in response to the report within the same
round; propose changes to the user, and measure them in a new round.
