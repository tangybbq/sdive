# security-dive — plan

Proactive, LLM-driven security analysis of embedded codebases — **MCUboot first,
then Zephyr** — with durable tracking of *what has been examined, through which
lens, at what version*, so the work can be incremental and can gate incoming
changes.

## Relationship to the sibling projects

- **zepsec** (`../zepsec`) looks *backward*: it finds already-merged **silent
  fixes**. security-dive looks *forward*: **live bugs in current code**, and
  **bugs introduced by incoming changes**.
- Analysis and tracking live **here**. A verified finding is *exported* in a form
  zepsec/`ghsa file` can take (the `analysis/mcuboot_findings/<slug>/` shape) for
  advisory drafting, CVE and fix authoring. security-dive never files anything
  itself.
- Reused from zepsec: the MCUboot **threat model** (`../zepsec/threat-model.md`,
  properties P1–P6, attacker classes A1–A3) is the bar every verdict must name.
  It is referenced in place (its hash is recorded per run), with the goal of
  moving it into MCUboot's own documentation (see Threat model upstreaming
  below), after which `config.toml` points at that copy instead;
  `ghsa.db`, the Vanessa disclosures and prior findings form the **dedup corpus**.

## Execution model: skills do the thinking, the CLI does the bookkeeping

The analysis runs **interactively in Claude Code** (the plan that makes Mythos
affordable is interactive-only), so there are **no direct API calls** in this
project. The split:

- **`sdive` (Python, uv, Click)** — deterministic, no LLM. Owns repo mirrors and
  snapshots, unit extraction, the SQLite ledger, the work queue, brief/context
  generation, *validated* ingestion of agent output, coverage reports, diff→unit
  mapping, and export to zepsec.
- **Claude Code skills + subagents (`.claude/`)** — the analysis. A skill asks
  `sdive next` for a work item, makes sure the snapshot exists, dispatches a
  subagent with a brief, the subagent writes a JSON result to a staging dir, and
  the skill calls `sdive record`, which validates it against a pydantic schema
  before anything touches the ledger. The model never writes the DB directly.
- Subagents use `model: inherit`, so the session's `/model` (Mythos) applies; the
  result JSON carries the model ID the agent reports, recorded per run.
- Throughput is bounded by plan usage, not dollars. Skills take `[id | N | all]`
  like `/zepsec-analyze`, and `/loop` can drain a queue within a session.
  Everything is resumable: a crash loses at most the in-flight item.

Planned skills / agents (names provisional):

| Skill | Subagent | Job |
|---|---|---|
| `/sdive-sweep` | `sdive-auditor` | whole-source pass over a project through one lens (MCUboot) |
| `/sdive-dive` | `sdive-auditor` | deep dive on one unit / entry point, following data flow |
| `/sdive-verify` | `sdive-verifier` | **blind**, adversarial refutation of one hypothesis |
| `/sdive-change` | `sdive-change-reviewer` | review a commit range or PR head against the dossiers |
| `/sdive-triage` | `sdive-triager` (cheap model) | Zephyr attack-surface scoring of units |

## Core data model — units, lenses, the ledger

SQLite at `analysis/sdive.db`.

- **Unit** — the thing analyzed: a file, a function, or a named cluster
  (e.g. "TLV iteration"). Extracted with tree-sitter (C). Each unit has a
  **content hash per snapshot**, so unchanged code keeps its coverage across
  commits, and a change invalidates exactly the units it touches.
- **Area** — a grouping of units with an owner/priority (MCUboot: hand-written
  `projects/mcuboot/areas.toml`; Zephyr: derived from `MAINTAINERS.yml`).
- **Lens** — a versioned question (markdown in `projects/<p>/lenses/`, identified
  by content hash). MCUboot lenses start from P1–P6 plus cross-cutting ones:
  attacker-controlled lengths/integer arithmetic, flash-read TOCTOU, swap/trailer
  state under power loss, config combinations that compile checks out
  (cf. `assert-guards-noop-ndebug`).
- **Run** — one skill invocation: kind, skill+agent file hashes, lens, model,
  snapshot SHA, timestamps, outcome.
- **Coverage** — `(unit, content_hash, lens, run) → clean | hypotheses | partial |
  error`. "Covered" means covered *at this hash under this lens version*.
- **Finding** — slug-keyed. Lifecycle:
  `hypothesis → verified | rejected | duplicate → exported → fixed`, with an event
  log. Every verified finding names property, attacker class, CWE, locations,
  and the snapshot it was found at. Rejections keep their reasoning.
- **Dossier** — per-area markdown (`analysis/dossiers/<p>/<area>.md`) that
  accumulates trust boundaries, invariants ("TLV length bounded at X"), and
  **cleared patterns** with the reason they are safe. Fed into every brief for
  that area; updated after each pass. This is what suppresses repeat false
  positives and what makes change review cheap.

## Reference trees and upstream notes

External components a project builds against (MCUboot: the `ext/mbedtls-3.6.0`
and `ext/mbedtls-4.1.0` submodules, plus 4.1's nested `tf-psa-crypto`) are
exported into snapshots as **reference trees**: agents consult them to settle
API contracts, but they are never indexed, never counted in coverage, and never
the location of a finding. `sdive record` rejects a hypothesis with no location
in indexed project code. Claims that depend on library behaviour name the version
relied on (Zephyr builds use Zephyr's own crypto modules, not MCUboot's pins).

A defect noticed *inside* a reference tree is recorded as an **upstream note**
(`upstream_notes` table, `sdive upstream`), with the component's URL and pinned
commit. This will matter much more for Zephyr, which pulls in many external
modules via west; tracking and filing upstream notes is future work. Code a
project vendors directly (MCUboot's `ext/tinycrypt`, `fiat`, `mbedtls-asn1`,
`nrf`) is *not* a reference tree: the project ships it, so it is audit scope
(a later tier).

For Zephyr, reference trees will come from `west.yml` projects rather than
`.gitmodules`.

## Repos and confidentiality

- **Never touch the user's checkouts.** Each project gets a private mirror at
  `work/mirrors/<p>.git` (cloned with `--reference` to the local repo, then
  dissociated), so PR refs can be fetched freely. Analysis runs against
  read-only snapshots `work/snapshots/<p>/<sha>/` exported with `git archive`.
  `work/` is disposable.
- **`analysis/` is private**: gitignored by this repo, with its own nested repo
  for history (as zepsec does). It holds the DB, findings, dossiers, run records.
  The top-level repo is tooling only.
- Findings in released code are live, embargoed vulnerabilities: nothing about
  them goes in a public PR, issue, or commit message. The one public channel is
  review comments on **unmerged** PRs (see the disclosure policy below).

## Disclosure policy for change findings

Handling depends on where the buggy code has got to:

| State of the introducing change | Handling |
|---|---|
| **Unmerged PR** | Comment on the PR. The code isn't in anyone's product yet. |
| **Merged, not yet in a release** | Just fix it with an ordinary fix PR. No GHSA or CVE. |
| **In a release** | A vulnerability like any other: GHSA draft through zepsec/`ghsa file`, embargo, CVE. |

`sdive` works out the state per finding (is the introducing commit merged? is it
in any release tag?) and records which path was taken. PR comments are drafted
by the skill and shown to the user before posting, and say only what's needed
for the author to fix it.

## Phases

### Phase 0 — skeleton (no LLM) — done
Config; `sdive mirror` / `sdive snapshot`; DB schema; tree-sitter unit extraction
for MCUboot; areas in `projects/mcuboot/project.toml`; `sdive units` /
`sdive coverage` reports; `sdive next` / `sdive record` with the result schemas.

Notes from building it:
- **Preprocessor.** tree-sitter doesn't preprocess, and MCUboot puts `#if` in
  signatures and bodies. The extractor parses renderings that keep one branch
  per `#if` group (first, last, then the exact branch path for any column-0 `}`
  still unaccounted for) and merges by name and line. On MCUboot `main` this
  gives 462 functions, and every `.c` file's count matches its column-0 `}`s.
- **Unit keys** are `path::func`, with `@2`, `@3` for `#if` variants in line
  order. Function hashes cover the original lines, so a change in any branch
  invalidates the unit.
- **Snapshots** are `git archive` exports. Submodules are included only when
  listed as reference trees (below).
- **Batching**: a dive run takes the uncovered functions of one file
  (highest priority first, capped at 40 functions / 600 lines); a sweep takes
  whole areas in priority order up to ~3000 lines (one area at least). Runs are
  the unit of cost and of stopping: skills take a run count or `--minutes`
  (agent-minutes, converted to runs from median recorded run times pooled
  over all ledgers — about $0.60 per agent-minute at list price for Mythos,
  from the first 21-run verify session), `sdive todo` estimates what is left,
  and coverage carries across sessions (interrupted runs are recorded or
  abandoned at the start of the next). `--parallel P` keeps up to four runs in
  flight; concurrent dives are started in different areas, because dossier
  notes only reach other runs once recorded.

### Phase 1 — MCUboot calibration
Write the auditor/verifier agents and the first lenses. **Recall benchmark:** run
blind at `511dc9e2` (the Vanessa scan commit) without feeding the disclosures,
then compare against the 46 known claims and our own validated verdicts. Tune
prompts on misses and false positives before spending effort on `main`.

Built (tooling); the benchmark rounds themselves run in a Mythos session:
- **Lenses** (`projects/mcuboot/lenses/`): `holistic` for dives; `memory-safety`,
  `authenticity` (P1/P5), `rollback` (P2), `secrets` (P3/P4), `recovery` (A2/P6),
  `upgrade-state` for sweeps. Caveat: written after seeing the truth-set titles;
  kept to general vulnerability classes, with the two most item-shaped lines
  removed, but not independent of the benchmark.
- **Agents** (`.claude/agents/`): `sdive-auditor`, `sdive-verifier` — Read, Grep,
  Glob, Write only (no Bash), read-only boundaries stated in the prompt.
- **Skills**: `/sdive-dive`, `/sdive-sweep`, `/sdive-verify`, `/sdive-bench`.
- **Agent threat model**: `projects/mcuboot/threat-model.md`, derived from
  zepsec's with all finding references and per-finding re-dispositions removed
  (the original names benchmark answers).
- **Ground truth**: `sdive bench import` from zepsec corpora, honouring
  `override.json`; at `511dc9e2`, 9 validated bugs (plus overridden cf009,
  cf010, cf011, #17 → 15 tp overall), 18 refuted traps, out-of-scope items
  excluded. Imported from the 2026-08-11 precutover copy; re-import from a fresh
  `pull-snapshot.sh` if verdicts have changed since.
- **Blindness**: `.claude/settings.json` denies Read on `analysis/truth/` and
  zepsec analysis dirs, agents have no Bash, and skills pass agents only the
  brief path. Tested 2026-11-12 from inside `sdive-auditor` (prompted to try):
  Read, Grep and Glob on the truth file and folder, the zepsec corpora and
  zepsec's threat model were all refused by the harness; a Grep over the parent
  `analysis/` silently skipped the denied subtree; reads of the snapshot and
  lenses worked. Not covered by deny rules: subprocesses (agents have no Bash).
- **Rounds** use disposable ledgers (`--ledger bench-...`), so prompt changes are
  measured in fresh rounds and nothing leaks into `main`.
- **Scoring** is by human judgement: location matches (same function, near,
  same file) are only candidates; `sdive bench judge` records which findings
  really raise each truth item, per round, in the ledger's `adjudication.json`.

Round 1 (2026-11-12, Mythos, partial: one memory-safety sweep pass + 10
holistic dives + verification of all 28 hypotheses). By manual reading, 6 of
13 in-scope validated bugs were raised and confirmed; no refuted trap was
raised as the same claim (one close call left for judgement); about a dozen
further verified findings match no truth item and need review against `main`.
Every miss was examined only by the single sweep (no dives reached those
areas); half of them are outside the memory-safety lens's class, and the rest
suggested one sweep over all 423 functions was too thin (125 came back
partial). Changes since: judged scoring, area-batched sweeps, narrow finding
locations in the auditor prompt. Not re-measured, to save usage; Phase 2
starts on `main` instead.

### Phase 2 — MCUboot deep dive at `main`
Core scope: `boot/bootutil` + `boot/boot_serial` + `boot/zephyr` (~25k lines,
fits comfortably in context).
0. **Carried findings** — `sdive carry` copies a benchmark round's verified
   findings into the main ledger as hypotheses at `main` (locations remapped
   by function key, provenance in `carried_from`), so the ordinary blind
   verify loop tells which are still live — cheaper than re-finding them.
1. **Sweeps** — each focused lens over the core source, a few areas per run.
2. **Entry-point dives** — image header/TLV parsing, serial recovery/SMP,
   swap-status and trailer reads, encrypted-key unwrap, `ext/` crypto glue.
3. **Verification** — every hypothesis gets an independent blind verifier.
4. **Dossiers** written/updated per area; verified findings deduped and exported.
Second tier afterwards: the other ports (espressif, cypress, nuttx, mynewt, mbed),
`ext/`, `scripts/imgtool`.

### Phase 3 — MCUboot pre-merge and post-merge
- `sdive prs sync` (via `gh`) lists open PRs on `mcu-tools/mcuboot` with head
  SHAs; a new or updated head is queued. `sdive commits sync` does the same for
  new commits on `main`.
- `/sdive-change` maps the diff → changed functions → units, adds **blast radius**
  (callers of changed validation helpers), and reviews the change against the
  area dossiers: *which recorded invariant does this touch, and does it still
  hold?*
- Results under `analysis/changes/mcuboot/{pr-<n>,commit}/<sha>/`; merged changes
  invalidate coverage for the touched unit hashes.
- Findings follow the disclosure policy above: PR comment, quiet fix, or GHSA.

### Phase 4 — Zephyr breadth
- Mirror with `--reference ~/zephyrproject/zephyr`. Areas from `MAINTAINERS.yml`.
- Representative build configs → `compile_commands.json` → which code is
  actually built. Code nothing realistic builds sinks to the bottom. *Which
  configs count as representative is deferred to a discussion with the Zephyr
  security team.*
- `/sdive-triage` (cheap subagent) scores units for attacker reachability and
  parsing/length arithmetic; Mythos time goes to the top of the queue.
  Priority surfaces: IP/TCP/DNS, LwM2M/CoAP/MQTT, Bluetooth host + controller,
  USB device classes, the userspace syscall boundary (`z_vrfy_*`), drivers fed by
  external buses.
- Coverage reporting per area and lens.

### Phase 5 — Zephyr incremental
Post-merge change review on `main`, then PRs; possibly sharing the commit walk
with zepsec (one pass asking "silent fix?" and "introduces something?").

## Threat model upstreaming (side track)

The zepsec threat model is written for triage: it carries finding IDs (cf009,
cf018) and verdict rules. To land it in MCUboot's docs (e.g. `docs/threat-model.md`):

1. Split it into a public part (security properties, attacker classes, the
   flash-write boundary, what is and isn't in scope) and internal triage notes
   that stay in zepsec.
2. Remove references to embargoed findings; replace them with general wording.
3. Propose it as an MCUboot docs PR. Once merged, point `config.toml` at the
   upstream file and make zepsec's copy a pointer plus its triage notes.

Phase 1–2 findings will show where the model is unclear, so the public version
should be better for having been used first.

## Open questions

1. Zephyr representative configs — deferred to a discussion with the team.
2. Exact zepsec hand-off schema — to be pinned when Phase 2 produces the first
   verified finding.
