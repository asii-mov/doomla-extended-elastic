"""Phase 7 multi-seed runner for the Doomla EDR eval.

Drives N seeds × M arms through the existing ``doomla`` task, computes a
deterministic ``ScoreResult`` for each run, and writes one
``runs/<date>/raw/<arm>-<seed>.json`` per (arm, seed). Companion
:mod:`aggregate` turns that pile of raw files into a single summary table.

Design choices that aren't obvious from the code:

* **In-process Inspect AI** (``inspect_ai.eval``) rather than the
  ``inspect eval`` CLI. The returned ``EvalLog`` carries the per-sample
  ``store`` (where Phase 4 dropped ``BlockEvent``s) and the messages
  needed to reconstruct the command sequence — exfiltrating those from
  a subprocess-only log file would be strictly more work.

* **Serial, not parallel.** Two runs sharing one Elastic stack would
  cross-contaminate ``logs-endpoint.alerts-*``; the spec explicitly
  forbids parallelism. The compose stack stays up between runs so we
  don't pay 60–90s of warm-up per iteration.

* **Doomla compose reset between runs.** ``docker compose down -v`` on
  ``doomla-extended/.../compose.yaml`` — clears MySQL state, SSH host
  keys, and any pivot side-effects. Inspect Cyber will bring the
  sandbox back up on the next ``eval`` call.

* **Alert window = sample.started_at → sample.completed_at + grace.**
  The sample's own timestamps are the tightest legitimate filter and
  guarantee disjoint windows across back-to-back runs. The grace tail
  catches detection-engine rollup latency.

* **Score computed out-of-band**, not via an Inspect Scorer adapter.
  ``task.py`` still uses ``includes()`` so the Inspect score column is
  the simple flag-present check; the rich :class:`scorer.ScoreResult`
  is computed here from the eval log + ES alert read and persisted
  alongside.

The ``--arms`` default omits ``tier1_baseline`` — Tier 1 was removed
2026-05-20 (see ``project_tier_design`` memory). The runner still
accepts it on the CLI if a future user wants to re-add a no-EDR control,
but ``Tier`` doesn't define it so ``parse_tier`` will reject it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from inspect_ai import eval as inspect_eval
from inspect_ai.log import EvalLog
from inspect_ai.model import ChatMessageAssistant

from alert_reader import read_full_alert_log
from defended_bash import BLOCK_EVENTS_KEY
from es_client import load_env, make_client
from scorer import RunLog, score
from stack import start_stack
from task import DOOMLA_FLAG, doomla
from tiers import Tier, parse_tier

DEFAULT_MODEL = "anthropic/claude-opus-4-7"
DEFAULT_ARMS = ("tier2_monitor", "tier3_block", "tier3_informed")

REPO_ROOT = Path(__file__).resolve().parent
DOOMLA_COMPOSE = REPO_ROOT / "doomla-extended" / "evals" / "doomla" / "compose.yaml"

# Pad the alert window so DE-rule rollups landing just after the sample
# finishes still get attributed to the run. The Defend rule passthrough
# is documented at ~60s; 120s gives us a comfortable margin without
# letting the next run's alerts bleed in (back-to-back runs are at least
# the Doomla compose down/up wall-clock apart — minutes, not seconds).
ALERT_GRACE_TAIL_S = 120.0

# Per-sample wall-clock ceiling, passed to ``inspect_eval(time_limit=...)``.
# 1 hour is generous against typical wall times (8–45 min depending on arm).
# A run that exceeds this returns ``log.status='error'``; the runner records
# it as an error row and continues — failing fast on hangs (one observed
# 2026-05-21: tier2_monitor seed 2 sat in the agent loop for 4 hours with
# no progress, blocking the batch).
SAMPLE_TIME_LIMIT_S = 3600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_iso_utc(value: str | datetime | None) -> datetime | None:
    """Coerce Inspect AI's ISO-string timestamps (or a raw datetime) to UTC.

    ``EvalSample.started_at`` / ``completed_at`` are typed as ``str |
    None`` in current Inspect versions but older versions emitted
    ``datetime`` directly — accept either so the runner survives a minor
    Inspect upgrade.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        # ``fromisoformat`` handles both naive and ``+00:00``/``Z``-style
        # offsets on Python 3.11+. The Inspect harness always writes UTC.
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _doomla_reset() -> None:
    """``docker compose down -v`` on the Doomla compose, if present.

    Inspect Cyber will bring the stack back up on the next ``eval``
    call. Missing compose file is non-fatal — useful for unit-testing
    the runner against a stubbed eval.
    """
    if not DOOMLA_COMPOSE.exists():
        return
    subprocess.run(
        [
            "docker", "compose", "-f", str(DOOMLA_COMPOSE),
            "down", "-v", "--remove-orphans",
        ],
        check=False,  # idempotent — non-zero on "nothing to remove" is fine
    )


def _extract_commands(sample: Any) -> list[str]:
    """Pull bash tool-call commands out of the assistant message stream.

    Typed ``Any`` rather than ``EvalSample`` so unit tests can pass in
    lightweight stand-ins without dragging the whole Inspect log model
    in. The fields accessed (``messages`` → assistant turns →
    ``tool_calls`` → ``arguments``) are stable across Inspect versions.
    """
    commands: list[str] = []
    for msg in sample.messages or []:
        if not isinstance(msg, ChatMessageAssistant):
            continue
        for tc in msg.tool_calls or []:
            # Both the plain ``bash()`` tool (Tier 2) and the defended
            # bash wrapper (Tier 3 variants) take the command under
            # ``cmd``; ``command`` is the upstream Inspect AI alias.
            args = tc.arguments or {}
            cmd = args.get("cmd") or args.get("command")
            if cmd:
                commands.append(str(cmd))
    return commands


def _store_value(sample: Any, key: str) -> Any:
    """Read a per-sample store key from the eval log.

    ``EvalSample.store`` is a ``dict[str, Any]`` in newer Inspect
    versions; older versions exposed a ``Store`` object with ``.get``.
    Handle both.
    """
    store_obj = sample.store
    if store_obj is None:
        return None
    if isinstance(store_obj, dict):
        return store_obj.get(key)
    getter = getattr(store_obj, "get", None)
    if callable(getter):
        return getter(key)
    return None


def _run_one(
    *,
    arm: str,
    seed: int,
    model: str,
    variant: str,
    limit: int | None,
    out_raw_dir: Path,
    log_dir: Path,
) -> dict[str, Any]:
    """Execute one (arm, seed) and return the persisted record."""
    tier_enum = parse_tier(arm)  # rejects unknown arms loudly

    wall_start = _utcnow()
    logs: list[EvalLog] = inspect_eval(
        doomla(tier=tier_enum.value, variant=variant),
        model=model,
        log_dir=str(log_dir),
        limit=limit,
        time_limit=SAMPLE_TIME_LIMIT_S,
    )
    wall_end = _utcnow()

    if not logs:
        raise RuntimeError(f"inspect_eval returned no logs for {arm}/{seed}")
    log = logs[0]
    samples = log.samples or []
    if not samples:
        raise RuntimeError(
            f"inspect_eval produced no samples for {arm}/{seed} "
            f"(eval status={log.status!r}, error={log.error!r})"
        )
    sample = samples[0]

    # Prefer the sample's own timestamps for the alert window — they
    # bracket the actual model interaction tighter than wall-clock.
    started = _parse_iso_utc(sample.started_at) or wall_start
    completed = _parse_iso_utc(sample.completed_at) or wall_end
    run_start = started
    run_end = completed + timedelta(seconds=ALERT_GRACE_TAIL_S)

    env = load_env()
    agent_id = env.get("MONITORED_AGENT_ID")
    if not agent_id:
        raise RuntimeError(
            "MONITORED_AGENT_ID missing from .harness/elastic.env — "
            "re-run setup_elastic.py to enrol the Defend agent."
        )
    es = make_client(env=env)
    alerts = read_full_alert_log(
        es,
        agent_id=agent_id,
        container_ids=[],  # rely on Phase 1 structural exclusion; per-sample
                           #  container-id capture is a known follow-up
        run_start=run_start,
        run_end=run_end,
    )

    commands = _extract_commands(sample)
    final_output = (sample.output.completion if sample.output else "") or ""
    block_events = _store_value(sample, BLOCK_EVENTS_KEY) or []

    result = score(
        RunLog(commands=commands, final_output=final_output),
        alerts,
        block_events,
        flag_markers=(DOOMLA_FLAG, "flag{"),
    )

    record: dict[str, Any] = {
        "arm": arm,
        "seed": seed,
        "model": model,
        "variant": variant,
        "run_start": _iso(run_start),
        "run_end": _iso(run_end),
        "sample_started_at": _iso(started),
        "sample_completed_at": _iso(completed),
        "wall_start": _iso(wall_start),
        "wall_end": _iso(wall_end),
        "log_location": getattr(log, "location", None),
        "log_status": log.status,
        "log_error": str(log.error) if log.error else None,
        "alert_count": len(alerts),
        "command_count": len(commands),
        "block_event_count": len(block_events),
        "score": asdict(result),
    }

    # Inspect AI surfaces interruptions (credit exhaustion, message-limit
    # hits, tool-timeout cascades) as ``log.status == "error"`` but still
    # produces a sample with whatever messages/store accumulated before
    # the interrupt. Tag the record with ``error`` so aggregate.py treats
    # it as an error row rather than averaging partial data into the per-
    # arm means; the partial score stays in the file for manual triage.
    if log.status != "success":
        record["error"] = (
            f"inspect log status={log.status!r}; "
            f"truncated at {len(commands)} commands"
        )

    out_path = out_raw_dir / f"{arm}-{seed}.json"
    out_path.write_text(json.dumps(record, indent=2))
    return record


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run N seeds × M arms of the Doomla EDR eval and persist raw scores.",
    )
    parser.add_argument(
        "--seeds", type=int, required=True,
        help="Number of seeds per arm (≥1). Spec requires ≥3 for publication.",
    )
    parser.add_argument(
        "--start-seed", type=int, default=0,
        help="Index of the first seed. Use to extend a prior batch — e.g. "
             "--seeds 4 --start-seed 1 runs seeds 1..4, leaving an existing "
             "seed-0 record untouched. Default 0.",
    )
    parser.add_argument(
        "--arms", type=str, default=",".join(DEFAULT_ARMS),
        help=f"Comma-separated tier names. Default: {','.join(DEFAULT_ARMS)}.",
    )
    parser.add_argument(
        "--out", type=Path, required=True,
        help="Output directory. Raw scores go to <out>/raw/, eval logs to <out>/inspect_logs/.",
    )
    parser.add_argument(
        "--model", type=str, default=DEFAULT_MODEL,
        help=f"Inspect AI model spec. Default: {DEFAULT_MODEL}.",
    )
    parser.add_argument(
        "--variant", type=str, default="example",
        help="Doomla dataset variant. Default: example.",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Inspect AI per-task sample limit. Default: no limit (run all samples).",
    )
    parser.add_argument(
        "--skip-stack-start", action="store_true",
        help="Skip the Elastic compose bring-up (operator brought it up by hand).",
    )
    parser.add_argument(
        "--skip-doomla-reset", action="store_true",
        help="Skip the Doomla compose down/up between runs (debugging only).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.seeds < 1:
        print("error: --seeds must be ≥ 1", file=sys.stderr)
        return 2

    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    if not arms:
        print("error: --arms produced no entries", file=sys.stderr)
        return 2
    # Validate arms before any expensive setup.
    for a in arms:
        try:
            parse_tier(a)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    out_dir: Path = args.out.resolve()
    raw_dir = out_dir / "raw"
    log_dir = out_dir / "inspect_logs"
    raw_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    if not args.skip_stack_start:
        start_stack()

    manifest: dict[str, Any] = {
        "started_at": _iso(_utcnow()),
        "model": args.model,
        "variant": args.variant,
        "arms": arms,
        "seeds": args.seeds,
        "runs": [],
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    exit_code = 0
    for arm in arms:
        for seed in range(args.start_seed, args.start_seed + args.seeds):
            label = f"{arm}/{seed}"
            print(f"[run_all] starting {label}", flush=True)
            if not args.skip_doomla_reset:
                _doomla_reset()
            try:
                rec = _run_one(
                    arm=arm,
                    seed=seed,
                    model=args.model,
                    variant=args.variant,
                    limit=args.limit,
                    out_raw_dir=raw_dir,
                    log_dir=log_dir,
                )
            except Exception as exc:  # noqa: BLE001 — keep the batch alive
                exit_code = 1
                err = {
                    "arm": arm,
                    "seed": seed,
                    "error": f"{type(exc).__name__}: {exc}",
                    "wall_time": _iso(_utcnow()),
                }
                (raw_dir / f"{arm}-{seed}.error.json").write_text(
                    json.dumps(err, indent=2)
                )
                manifest["runs"].append(err)
                print(f"[run_all] FAILED {label}: {exc}", file=sys.stderr, flush=True)
            else:
                if rec.get("error"):
                    # Inspect-side interrupt (credit, message-limit, tool
                    # cascade). Tag exit code so a CI batch fails the run,
                    # but keep the partial record around for triage.
                    exit_code = 1
                    manifest["runs"].append({
                        "arm": rec["arm"],
                        "seed": rec["seed"],
                        "error": rec["error"],
                        "log_status": rec["log_status"],
                        "command_count": rec["command_count"],
                        "log_location": rec["log_location"],
                    })
                    print(
                        f"[run_all] INTERRUPTED {label}: "
                        f"log_status={rec['log_status']} at "
                        f"{rec['command_count']} cmds",
                        file=sys.stderr, flush=True,
                    )
                else:
                    manifest["runs"].append({
                        "arm": rec["arm"],
                        "seed": rec["seed"],
                        "completion": rec["score"]["completion"],
                        "alert_count": rec["alert_count"],
                        "block_event_count": rec["block_event_count"],
                        "log_location": rec["log_location"],
                    })
                    print(
                        f"[run_all] done {label}: completion="
                        f"{rec['score']['completion']} alerts={rec['alert_count']} "
                        f"blocks={rec['block_event_count']}",
                        flush=True,
                    )
            # Re-write manifest on every iteration so a mid-batch crash
            # still leaves a usable record.
            manifest_path.write_text(json.dumps(manifest, indent=2))

    manifest["finished_at"] = _iso(_utcnow())
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
