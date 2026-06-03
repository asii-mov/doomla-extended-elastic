"""Phase 5 scorer tests.

Fixture-driven (one JSON per case in ``scorer_fixtures/``) covering every
pivot label + every resilience value, plus three module-level
invariants: determinism on re-run, scorer carries no LLM-call imports,
and the dict ↔ BlockEvent bridge that Phase 4 → Phase 7 relies on works
either way.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from alert_schema import SEVERITY_RANK, Alert
from defended_bash import BlockEvent
from scorer import RunLog, ScoreResult, score

FIXTURES_DIR = Path(__file__).parent / "scorer_fixtures"


def _alert_from_fixture(d: dict[str, Any]) -> Alert:
    """Build a minimal Alert from a fixture dict.

    Only the fields the scorer reads are required; the rest get
    deterministic defaults so the scorer's logic isn't sensitive to
    timestamps or per-event noise the fixtures don't model.
    """
    severity = d.get("severity", "medium")
    if severity not in SEVERITY_RANK:
        raise ValueError(f"fixture severity {severity!r} not in SEVERITY_RANK")
    return Alert(
        timestamp=None,
        surface=d.get("surface", "raw"),
        severity=severity,
        severity_rank=SEVERITY_RANK[severity],
        event_type=d.get("event_type", "denied"),
        event_code=d.get("event_code", ""),
        rule_name=d.get("rule_name", ""),
        container_id=d.get("container_id"),
    )


def _block_from_fixture(d: dict[str, Any]) -> BlockEvent:
    return BlockEvent(
        call_index=d["call_index"],
        cmd=d["cmd"],
        trigger=d.get("trigger", "in_loop"),
        alert_dedup_keys=d.get("alert_dedup_keys", []),
        rule_names=d.get("rule_names", []),
        severities=d.get("severities", []),
        container_ids=d.get("container_ids", []),
        triggered_at=d.get("triggered_at", "2026-05-20T12:00:00+00:00"),
    )


def _load_fixture(name: str) -> dict[str, Any]:
    with (FIXTURES_DIR / f"{name}.json").open() as f:
        return json.load(f)


def _score_fixture(fx: dict[str, Any]) -> ScoreResult:
    run_log = RunLog(
        commands=list(fx["run_log"]["commands"]),
        final_output=fx["run_log"].get("final_output", ""),
    )
    alerts = [_alert_from_fixture(a) for a in fx.get("alerts", [])]
    blocks = [_block_from_fixture(b) for b in fx.get("block_events", [])]
    markers = tuple(fx.get("flag_markers", ("flag{", "FLAG{", "CTF{")))
    return score(run_log, alerts, blocks, flag_markers=markers)


FIXTURE_NAMES = [p.stem for p in sorted(FIXTURES_DIR.glob("*.json"))]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture(name: str) -> None:
    fx = _load_fixture(name)
    result = _score_fixture(fx)
    expected = fx["expected"]

    assert result.completion is expected["completion"], (
        f"{name}: completion mismatch (got {result.completion})"
    )
    assert result.alert_count == expected["alert_count"], (
        f"{name}: alert_count mismatch (got {result.alert_count})"
    )
    assert result.distinct_rules == expected["distinct_rules"], (
        f"{name}: distinct_rules mismatch (got {result.distinct_rules})"
    )
    assert result.block_count == expected["block_count"], (
        f"{name}: block_count mismatch (got {result.block_count})"
    )
    assert result.resilience == expected["resilience"], (
        f"{name}: resilience mismatch (got {result.resilience})"
    )
    assert result.pivot == expected["pivot"], (
        f"{name}: pivot mismatch (got {result.pivot!r}, "
        f"evidence={result.pivot_evidence!r})"
    )
    if "pivot_evidence_equals" in expected:
        assert result.pivot_evidence == expected["pivot_evidence_equals"]
    if "pivot_evidence_contains" in expected:
        assert expected["pivot_evidence_contains"] in result.pivot_evidence, (
            f"{name}: evidence {result.pivot_evidence!r} missing "
            f"substring {expected['pivot_evidence_contains']!r}"
        )


def test_all_pivot_labels_covered() -> None:
    """Spec demands fixtures for every pivot label; guard against regression."""
    pivots = {_load_fixture(n)["expected"]["pivot"] for n in FIXTURE_NAMES}
    assert pivots == {"repeat", "substitute", "escalate", "give-up", "n/a"}


def test_all_resilience_values_covered() -> None:
    """Spec demands fixtures for every resilience value (-1, 0, 1)."""
    resiliences = {_load_fixture(n)["expected"]["resilience"] for n in FIXTURE_NAMES}
    assert resiliences == {-1, 0, 1}


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_determinism(name: str) -> None:
    """Calling score() twice on the same inputs returns equal ScoreResults."""
    fx = _load_fixture(name)
    a = _score_fixture(fx)
    b = _score_fixture(fx)
    assert a == b, f"{name}: non-deterministic ScoreResult"


def test_block_event_dict_bridge() -> None:
    """Phase 4 stores asdict() dicts in the Inspect store; score() should
    accept those without explicit conversion."""
    fx = _load_fixture("pivot_substitute")
    run_log = RunLog(
        commands=list(fx["run_log"]["commands"]),
        final_output=fx["run_log"].get("final_output", ""),
    )
    alerts = [_alert_from_fixture(a) for a in fx["alerts"]]
    block_dicts = [asdict(_block_from_fixture(b)) for b in fx["block_events"]]

    via_dicts = score(run_log, alerts, block_dicts)
    via_objs = _score_fixture(fx)
    assert via_dicts == via_objs


def test_block_events_none_treated_as_empty() -> None:
    """Handoff contract: None and [] must be interchangeable."""
    run_log = RunLog(commands=["ls"], final_output="hello")
    assert score(run_log, [], None) == score(run_log, [], [])


def test_scorer_module_imports_no_llm_apis() -> None:
    """Constraint #6: no LLM-as-judge anywhere in the scorer."""
    src = (Path(__file__).parent / "scorer.py").read_text()
    forbidden = (
        "inspect_ai.model",
        "inspect_ai.generate",
        "inspect_ai.solver.generate",
        "from anthropic",
        "import anthropic",
        "from openai",
        "import openai",
    )
    for token in forbidden:
        assert token not in src, (
            f"scorer.py must not reference {token!r} (constraint #6: "
            "no LLM-as-judge)"
        )
