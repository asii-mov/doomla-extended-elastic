"""Unit tests for the Phase 7 aggregator.

Builds synthetic ``raw/*.json`` files and checks that:

* the JSONL is emitted in stable column order, one line per raw input;
* per-arm means use only OK records;
* error files are surfaced as rows with ``status: error`` and counted
  in the summary table's N cell;
* pivot distribution renders deterministically.

No live ES, no Inspect AI, no docker — all of aggregate's behaviour is
file IO over the spec'd record shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import aggregate


def _write_ok(raw_dir: Path, *, arm: str, seed: int, **score_overrides) -> None:
    score = {
        "completion": True,
        "alert_count": 5,
        "distinct_rules": 3,
        "block_count": 0,
        "resilience": 0,
        "pivot": "n/a",
        "pivot_evidence": "",
    }
    score.update(score_overrides)
    record = {
        "arm": arm,
        "seed": seed,
        "model": "test/fake",
        "variant": "example",
        "run_start": "2026-05-20T12:00:00+00:00",
        "run_end": "2026-05-20T12:05:00+00:00",
        "alert_count": score["alert_count"],
        "command_count": 7,
        "block_event_count": score["block_count"],
        "score": score,
        "log_location": f"logs/{arm}-{seed}.eval",
    }
    (raw_dir / f"{arm}-{seed}.json").write_text(json.dumps(record))


def _write_err(raw_dir: Path, *, arm: str, seed: int) -> None:
    (raw_dir / f"{arm}-{seed}.error.json").write_text(json.dumps({
        "arm": arm,
        "seed": seed,
        "error": "RuntimeError: synthetic",
    }))


def test_aggregates_three_arms_with_means(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    _write_ok(raw, arm="tier2_monitor", seed=0, alert_count=10, distinct_rules=4)
    _write_ok(raw, arm="tier2_monitor", seed=1, alert_count=20, distinct_rules=6)
    _write_ok(raw, arm="tier3_block",   seed=0, alert_count=8,  block_count=2,
              resilience=1, pivot="substitute", completion=True)
    _write_ok(raw, arm="tier3_informed", seed=0, alert_count=4, completion=False,
              resilience=-1, pivot="give-up")

    rc = aggregate.main([str(tmp_path)])
    assert rc == 0

    jsonl_rows = [
        json.loads(line)
        for line in (tmp_path / "aggregate.jsonl").read_text().splitlines()
    ]
    assert len(jsonl_rows) == 4
    # Stable column order
    keys = list(jsonl_rows[0].keys())
    assert keys == list(aggregate.JSONL_COLUMNS)

    md = (tmp_path / "summary.md").read_text()
    assert "`tier2_monitor`" in md
    assert "`tier3_block`" in md
    assert "`tier3_informed`" in md
    # Mean alert count for tier2: (10 + 20) / 2 = 15.00
    assert "15.00" in md
    # Tier3_block had one substitute pivot — should render in the pivot cell
    assert "substitute=1/1" in md


def test_error_rows_surface_in_summary(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    _write_ok(raw, arm="tier2_monitor", seed=0, alert_count=10)
    _write_err(raw, arm="tier2_monitor", seed=1)
    _write_err(raw, arm="tier3_block", seed=0)

    aggregate.main([str(tmp_path)])

    md = (tmp_path / "summary.md").read_text()
    # tier2_monitor row should show 1/2 with an err marker; tier3_block 0/1 err
    assert "1/2 (1 err)" in md
    assert "0/1 (1 err)" in md

    # Error rows must appear in jsonl too, with status=error
    rows = [
        json.loads(line)
        for line in (tmp_path / "aggregate.jsonl").read_text().splitlines()
    ]
    statuses = sorted([r["status"] for r in rows])
    assert statuses == ["error", "error", "ok"]


def test_missing_raw_dir_returns_error(tmp_path, capsys):
    rc = aggregate.main([str(tmp_path / "does-not-exist")])
    assert rc == 2
    assert "does not exist" in capsys.readouterr().err


def test_empty_raw_dir_produces_empty_jsonl_and_dash_table(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()

    rc = aggregate.main([str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "aggregate.jsonl").read_text() == ""
    md = (tmp_path / "summary.md").read_text()
    # Empty body row used when nothing aggregated
    assert "— | — | — | — | — | — | — | —" in md
