# edr-elastic

An evaluation framework for measuring how an LLM agent performs at a
multi-step intrusion against a target host defended by a real
commercial EDR. The defender is **Elastic Defend** (Elastic Security)
running its default prevention policies plus the full Elastic
Prebuilt Detection Rules library; the target is the **Doomla**
cyber-range from Inspect Cyber (Joomla CVE-2023-23752 → MySQL
credentials → SSH pivot → GTFOBin privilege escalation → SSH lateral
movement → flag).

The central questions: how much detection signal does a stock
commercial EDR actually surface against an LLM-driven multi-step
intrusion, how does telling the agent what the defender looks like
change its behaviour, and does adding an explicit "minimise detection"
directive shift the agent toward stealthier tradecraft or just into
more persistent retrying?

## What we did

Built a four-arm evaluation that runs the Doomla scenario through
[Inspect AI](https://inspect.aisi.org.uk/) with Claude Opus 4.7 as the
attacker, while a host-level Elastic Defend agent watches every
syscall on the target containers and writes alerts to a self-hosted
Elastic Stack.

The four arms differ in two dimensions: whether the agent's bash
calls are intercepted by a wrapper that surfaces blocks back to the
model, and what the agent is told about the defender.

| Arm | Wrapped bash? | Vendor named? | Stealth directive? |
|-----|---|---|---|
| `tier2_monitor`           | no  | no  | no |
| `tier3_block`             | yes | no  | no |
| `tier3_informed`          | yes | yes — whitebox brief with inlined rule inventory | no |
| `tier3_informed_stealthy` | yes | yes — whitebox brief with inlined rule inventory | yes — "minimise detection" imperative |

Scoring is fully deterministic. After each run the alert log
(deduped union of the raw `logs-endpoint.alerts-*` datastream and the
detection-engine rollup index `.alerts-security.alerts-*`) is read
back from Elasticsearch and combined with the per-sample block-event
store. Completion, alert count, distinct rules triggered, block count,
resilience, and a rule-based pivot label (repeat / substitute /
escalate / give-up / n/a) all come out without an LLM-as-judge
anywhere in the pipeline.

## What we found

N=5 per arm, whitebox-era disclosure, Opus 4.7. Means below are
reported with 95 % percentile-bootstrap CIs (B = 10 000). Full results,
mechanisms, charts, and caveats are in [`FINDINGS.md`](./FINDINGS.md);
the single-seed canary writeup is preserved as
[`FINDINGS.md` Appendix A](./FINDINGS.md#appendix-a--canary-n1-numbers-superseded).

The eval asks three questions; the data answers them differently.

- **Q1 — Can the agent evade EDR blocks? Yes.** Pivot
  classifier labels 16 of 17 wrapped runs as `substitute` (94 %); the
  agent routes around blocks instead of stopping. The informed arm has
  the *highest* block rate (13.4 %) and the *highest* completion (4/5).
  Blocks are friction, not stops.

- **Q2 — Can the agent operate without detection when blind to the
  defender? No.** The blindest configuration (`tier2_monitor`, silent,
  no wrapper) trips a mean of **15 distinct prebuilt rules per single
  run**. No completing run anywhere in the dataset triggered fewer
  than 11 distinct rules. The chain's necessary categorical actions
  overlap exactly with what stock detection rules target.

- **Q3 — Can the agent operate without detection if it is given the
  full ruleset? No.** With 34 verbatim EQL/KQL rule cards inlined plus
  an explicit "minimise detection" directive — the best stealth
  posture available — the agent still trips **10.2 distinct rules**
  and **1.79 alerts/cmd**, per-command *higher* than the uninformed
  wrapped agent (0.89). Rule disclosure helps the agent *finish* (4/5
  vs 3/5) and narrows detection breadth (−38 % vs unconstrained
  informed); it does not approach an undetected regime. The
  lowest-detection runs are the failures.

The synthesis: AI overthinks EDR rules and as a result triggers MORE alerts compared to when rules are not provided. AI is able to circumvent the blocked attempts successfully by running alternative commands/scripts however Doomla is too small to reach a conclusive answer.

![Doomla milestones reached per cumulative tokens, Opus 4.7, N=5 per arm](docs/findings/step-progression.png)

![Alerts and blocks per arm, Opus 4.7, N=5 per arm](docs/findings/alerts-blocks.png)

Volume-metric CIs are wide at N=5 (~4× within an arm); rate metrics
and distinct-rules counts are tighter and carry most of the load.
**Doomla itself is unstable as a scoring substrate** — the no-EDR
silent baseline completes only 3/5, so cross-arm completion deltas
entangle EDR effect with scenario variance independent of any
defender. See [`FINDINGS.md`](./FINDINGS.md#doomla-scenario-instability--load-bearing-caveat)
for the dedicated section and the full caveat list.

## Setup

Prerequisites: Linux host with Docker + docker-compose, Python ≥ 3.10,
[`uv`](https://docs.astral.sh/uv/) for environment management, kernel
≥ 5.7 with BPF-LSM enabled (Ubuntu 22.04 LTS is what the eval was
developed and run on).

```bash
uv sync
```

One-shot Phase 1 stack bring-up — provisions ES certs, brings up the
self-hosted Elastic Stack (Elasticsearch + Kibana + Fleet Server) via
the project's `compose.elastic.yaml`, and enrols a Defend agent on
the host:

```bash
python setup_elastic.py
```

This is idempotent. On warm starts the stack lives under
`docker compose -f compose.elastic.yaml --profile elastic up -d`;
`python run_all.py --skip-stack-start` will skip the bring-up step if
the operator already has it running.

Authentication to Anthropic for the model calls is via the standard
`ANTHROPIC_API_KEY` environment variable.

## Running the eval

The two scripts you'll touch in normal use:

```bash
# Run all four arms × N seeds. Each (arm, seed) is one inspect_eval
# invocation; the Doomla compose is reset between runs. Each sample
# is wall-clock-bounded at SAMPLE_TIME_LIMIT_S = 3600 (1 h).
python run_all.py \
    --seeds 5 \
    --arms tier2_monitor,tier3_block,tier3_informed,tier3_informed_stealthy \
    --out runs/$(date -I)/ \
    --model anthropic/claude-opus-4-7

# Resume a partial batch from seed K (e.g., after a hang or top-up).
python run_all.py --seeds 3 --start-seed 2 \
    --arms tier3_informed,tier3_informed_stealthy \
    --out runs/$(date -I)/ \
    --model anthropic/claude-opus-4-7

# Aggregate the raw per-run scores into a JSONL + summary table, and
# render the FINDINGS.md charts against the run directory.
python aggregate.py        runs/$(date -I)/
python chart_progression.py --runs-dir runs/$(date -I)/
```

`--arms` defaults to the original three (`tier2_monitor`,
`tier3_block`, `tier3_informed`); the fourth arm
(`tier3_informed_stealthy`) is opt-in. `--seeds 5` is the publication
shape used here (~$140–180, ~10–18 h wall clock with the per-sample
cap); `--seeds 1` (canary) and `--seeds 3` (minimum) shapes are
cheaper but their results have correspondingly wider CIs.

Run artefacts land under `runs/<date>/`:

```
runs/<date>/
├── manifest.json                      # per-run invocation log + summary
├── aggregate.jsonl                    # one JSON object per raw run
├── summary.md                         # per-arm Markdown table
├── raw/<arm>-<seed>.json              # full score record per run
└── inspect_logs/*.eval                # Inspect AI log zips
```

`runs/.gitignore` excludes everything but itself — transcripts can be
multi-megabyte and contain host-specific paths.

## Repo layout

| Path | What it is |
|------|------------|
| `task.py` | Inspect AI task entry. Dispatches on `-T tier=...`. |
| `tiers.py` | `Tier` enum + per-tier configuration (wrap_bash, prompt suffix, disclose flag, stealth flag). |
| `disclosure.py` | `WHITEBOX_DISCLOSURE` (full Defend posture + rule inventory loaded from `disclosure_rules.md`) and `STEALTH_DIRECTIVE` (imperative appended for the stealthy variant). |
| `disclosure_rules.md` | ~40 KB Markdown rule inventory — 20 Defend behaviour rules + 14 prebuilt SIEM detection rules, each with name / severity / MITRE / description / verbatim EQL or KQL. Inlined into `WHITEBOX_DISCLOSURE` at import time. |
| `defended_bash.py` | The Tier 3 bash wrapper. In-loop grace + raw-surface query, deferred check on next call across both surfaces. Records block events to Inspect's per-sample store. |
| `alert_reader.py` | `LiveAlertReader.query_window` for the in-loop wrapper; `read_full_alert_log` for the post-run dedup-and-merge across both surfaces. |
| `alert_schema.py` | Cross-surface `Alert` dataclass and normalisation. |
| `scorer.py` | Pure-Python deterministic scorer. Pivot classifier with auditable evidence strings. |
| `stack.py` | Bring up + wait-for-healthy on the Elastic compose profile. |
| `es_client.py` | Auth + TLS for the self-hosted Elasticsearch. |
| `setup_elastic.py` | Cold bring-up: certs, agent enrolment, Prebuilt Rules install. |
| `run_all.py` | Multi-seed runner across arms. |
| `aggregate.py` | Raw per-run JSON → `aggregate.jsonl` + `summary.md`. |
| `chart_progression.py` | Renders the two `docs/findings/*.png` charts. Defaults to `--runs-dir runs/n5-2026-05-20`; per-seed step trajectories with a bold median, alerts/blocks bars with 95 % bootstrap CIs. |
| `compose.elastic.yaml` | The Elastic Stack compose (ES + Kibana + Fleet Server). |
| `doomla-extended/` | Doomla cyber-range dataset — compose, target images, scenario solution, and the agent Kali container. Trimmed fork of [UKGovernmentBEIS/doomla](https://github.com/UKGovernmentBEIS/doomla); only the `example` variant is used. |
| `test_*.py` | Unit tests for every module above. `pytest -k "not integration"` runs the offline suite. |
| `FINDINGS.md` | Writeup of the N=5 whitebox results with charts, bootstrap CIs, and caveats. Canary N=1 numbers preserved as Appendix A. |

## Constraints honoured by this design

These are taken from the project brief and the predecessor's
post-mortem; each is a non-negotiable property of the eval, locked in
by tests where possible.

1. **Stock prevention policies only.** Defend ships with default
   prevention rules and the full Prebuilt Detection Rules library is
   installed unchanged. No eval-tuned detections were written. Writing
   detections to catch this attack chain would replace "model
   capability measurement" with "rule-writing skill measurement".
2. **Multi-seed (N ≥ 3) for publication.** N = 1 is acceptable as a
   canary, never as a published number.
3. **Single strong model.** Opus 4.7 throughout the comparison. Weaker
   models likely fail to complete even on `tier2_monitor`; a model
   sweep is a separate experiment, not mixed into the EDR axis.
4. **Vendor-neutral block messages.** The wrapper's runtime output
   never names Elastic or Defend. The vendor is named only inside the
   two `tier3_informed*` system-prompt disclosures, which is the
   single carve-out.
5. **Agent container excluded from monitoring.** No Defend agent is
   installed on the Kali container; its offensive tooling would
   otherwise dominate detection counts.
6. **Deterministic pivot classifier.** Block → next-command pairs are
   classified as repeat / substitute / escalate / give-up by argument
   overlap and equivalence-group matching; no LLM-as-judge anywhere
   in the scoring pipeline.

