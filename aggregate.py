"""Phase 7 aggregator: raw per-run scores → JSONL + summary markdown.

Reads ``<runs_dir>/raw/*.json`` (the files written by :mod:`run_all`),
collates them by arm, and produces:

* ``<runs_dir>/aggregate.jsonl`` — one JSON object per raw run, in a
  stable column order so downstream tooling (pandas, jq, etc.) can rely
  on it. ``.error.json`` files are folded in too with a ``status:error``
  marker so a failed run never silently disappears.
* ``<runs_dir>/summary.md`` — a small Markdown table with one row per
  arm. Cells carry mean(±metric)|N=<count> formatting; pivot
  distribution is a percentage breakdown.

The aggregator is intentionally **single-pass and pure-Python** — no
pandas, no statistical tests beyond mean + count. The brief asks for N≥3
seeds; tighter bands (CIs, bootstrap) are future work once N is bigger.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Column order in the per-run JSONL — keep stable so jq/pandas pipelines
# can rely on positional access.
JSONL_COLUMNS = (
    "arm",
    "seed",
    "status",
    "completion",
    "alert_count",
    "distinct_rules",
    "block_count",
    "resilience",
    "pivot",
    "pivot_evidence",
    "command_count",
    "model",
    "variant",
    "run_start",
    "run_end",
    "log_location",
)


def _load_records(raw_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(raw_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            print(
                f"warning: skipping {path.name}: invalid JSON ({exc})",
                file=sys.stderr,
            )
            continue
        if path.name.endswith(".error.json") or "error" in data:
            records.append({
                "status": "error",
                "arm": data.get("arm"),
                "seed": data.get("seed"),
                "error": data.get("error"),
                "log_location": data.get("log_location"),
            })
        else:
            sc = data.get("score") or {}
            records.append({
                "status": "ok",
                "arm": data.get("arm"),
                "seed": data.get("seed"),
                "completion": sc.get("completion"),
                "alert_count": data.get("alert_count"),
                "distinct_rules": sc.get("distinct_rules"),
                "block_count": sc.get("block_count"),
                "resilience": sc.get("resilience"),
                "pivot": sc.get("pivot"),
                "pivot_evidence": sc.get("pivot_evidence"),
                "command_count": data.get("command_count"),
                "model": data.get("model"),
                "variant": data.get("variant"),
                "run_start": data.get("run_start"),
                "run_end": data.get("run_end"),
                "log_location": data.get("log_location"),
            })
    return records


def _mean_or_dash(values: list[float | int]) -> str:
    if not values:
        return "—"
    m = statistics.fmean(values)
    return f"{m:.2f}"


def _pivot_breakdown(values: list[str]) -> str:
    if not values:
        return "—"
    counts = Counter(values)
    total = sum(counts.values())
    parts = [
        f"{label}={n}/{total}"
        for label, n in counts.most_common()
    ]
    return ", ".join(parts)


def _summarise(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per-arm means / counts. Errored rows are excluded from the means but
    counted in an ``errors`` cell so they're visible in the table."""
    arms: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        arm = rec.get("arm") or "<unknown>"
        arms.setdefault(arm, []).append(rec)

    summary: dict[str, dict[str, Any]] = {}
    for arm, rows in arms.items():
        ok = [r for r in rows if r["status"] == "ok"]
        errors = [r for r in rows if r["status"] != "ok"]
        summary[arm] = {
            "n_total": len(rows),
            "n_ok": len(ok),
            "n_error": len(errors),
            "mean_completion": _mean_or_dash(
                [1.0 if r.get("completion") else 0.0 for r in ok]
            ),
            "mean_alert_count": _mean_or_dash(
                [r["alert_count"] for r in ok if r.get("alert_count") is not None]
            ),
            "mean_distinct_rules": _mean_or_dash(
                [r["distinct_rules"] for r in ok if r.get("distinct_rules") is not None]
            ),
            "mean_block_count": _mean_or_dash(
                [r["block_count"] for r in ok if r.get("block_count") is not None]
            ),
            "mean_resilience": _mean_or_dash(
                [r["resilience"] for r in ok if r.get("resilience") is not None]
            ),
            "pivot_distribution": _pivot_breakdown(
                [str(r["pivot"]) for r in ok if r.get("pivot")]
            ),
        }
    return summary


def _render_summary_md(summary: dict[str, dict[str, Any]]) -> str:
    header = (
        "| Arm | N (ok/total) | Mean completion | Mean alerts | "
        "Mean distinct rules | Mean blocks | Mean resilience | Pivot |\n"
        "|-----|--------------|-----------------|-------------|"
        "---------------------|-------------|-----------------|-------|\n"
    )
    rows: list[str] = []
    for arm in sorted(summary):
        s = summary[arm]
        n_cell = f"{s['n_ok']}/{s['n_total']}"
        if s["n_error"]:
            n_cell += f" ({s['n_error']} err)"
        rows.append(
            f"| `{arm}` | {n_cell} | {s['mean_completion']} | "
            f"{s['mean_alert_count']} | {s['mean_distinct_rules']} | "
            f"{s['mean_block_count']} | {s['mean_resilience']} | "
            f"{s['pivot_distribution']} |"
        )
    if not rows:
        rows.append("| — | — | — | — | — | — | — | — |")
    return (
        "# Doomla EDR eval — summary\n\n"
        "Means computed over OK runs (errored runs excluded from cells, "
        "shown in N column). Pivot distribution is a per-run label count "
        "across OK runs.\n\n"
        + header + "\n".join(rows) + "\n"
    )


def _emit_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    with path.open("w") as fh:
        for rec in records:
            row = {col: rec.get(col) for col in JSONL_COLUMNS}
            # Carry error string through too — it's not in the stable
            # column set but useful for triage.
            if rec.get("status") != "ok" and rec.get("error"):
                row["error"] = rec["error"]
            fh.write(json.dumps(row) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate raw per-run scores into JSONL + summary.md.",
    )
    parser.add_argument(
        "runs_dir", type=Path,
        help="Run output directory (the --out value passed to run_all.py).",
    )
    args = parser.parse_args(argv)

    runs_dir: Path = args.runs_dir.resolve()
    raw_dir = runs_dir / "raw"
    if not raw_dir.is_dir():
        print(f"error: {raw_dir} does not exist", file=sys.stderr)
        return 2

    records = _load_records(raw_dir)
    if not records:
        print(f"warning: no records under {raw_dir}", file=sys.stderr)

    jsonl_path = runs_dir / "aggregate.jsonl"
    summary_path = runs_dir / "summary.md"
    _emit_jsonl(records, jsonl_path)
    summary = _summarise(records)
    summary_path.write_text(_render_summary_md(summary))

    print(
        f"wrote {jsonl_path.relative_to(runs_dir)} ({len(records)} rows) "
        f"and {summary_path.relative_to(runs_dir)} ({len(summary)} arms)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
