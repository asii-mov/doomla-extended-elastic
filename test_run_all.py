"""Unit tests for Phase 7's ``run_all`` runner.

The runner's heaviest dependencies — Inspect AI's ``eval()`` and the
live Elasticsearch client — are stubbed out so the test exercises the
glue logic (per-run window capture, eval-log destructuring, score
computation, raw-file persistence, manifest update) without needing a
live stack or burning tokens. The live end-to-end is an operator
criterion (see ``phase-7-spec.md`` manual list).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import run_all
from alert_schema import Alert
from defended_bash import BLOCK_EVENTS_KEY


# ---- Fakes -----------------------------------------------------------------

@dataclass
class _FakeToolCall:
    function: str
    arguments: dict[str, Any]


@dataclass
class _FakeAssistant:
    role: str = "assistant"
    tool_calls: list[_FakeToolCall] = field(default_factory=list)


@dataclass
class _FakeUser:
    role: str = "user"
    tool_calls: list[_FakeToolCall] = field(default_factory=list)


@dataclass
class _FakeOutput:
    completion: str


@dataclass
class _FakeSample:
    messages: list[Any]
    output: _FakeOutput
    store: dict[str, Any]
    started_at: str | None
    completed_at: str | None


@dataclass
class _FakeLog:
    samples: list[_FakeSample]
    status: str = "success"
    error: Any = None
    location: str = "runs/test/inspect_logs/2026-05-20T12-00-00.eval"


def _make_sample(
    *, cmds: list[str], output: str, block_events: list[dict[str, Any]] | None = None,
    started: str = "2026-05-20T12:00:00+00:00",
    completed: str = "2026-05-20T12:01:00+00:00",
) -> _FakeSample:
    msgs: list[Any] = [_FakeUser()]
    for c in cmds:
        # An assistant calls the bash tool; the user-role message that
        # follows is the tool result. ``_extract_commands`` should only
        # ever look at the assistant turns.
        msgs.append(_FakeAssistant(tool_calls=[
            _FakeToolCall(function="bash", arguments={"cmd": c})
        ]))
        msgs.append(_FakeUser())
    return _FakeSample(
        messages=msgs,
        output=_FakeOutput(completion=output),
        store={BLOCK_EVENTS_KEY: list(block_events or [])},
        started_at=started,
        completed_at=completed,
    )


# Patch the ``isinstance`` check inside ``_extract_commands`` so our
# ``_FakeAssistant`` is treated as a ``ChatMessageAssistant``. Cleaner
# than mocking the imported symbol — the runner only uses
# ``ChatMessageAssistant`` for the role discriminant.
class _AssistantTypeShim:
    """Marker that the runner's ``isinstance`` check will succeed on
    instances of ``_FakeAssistant`` for the duration of a test."""

    def __init__(self, monkeypatch):
        original = run_all.ChatMessageAssistant
        monkeypatch.setattr(
            run_all, "ChatMessageAssistant", (original, _FakeAssistant),
        )


@pytest.fixture
def patched_runner(monkeypatch, tmp_path):
    """Install fakes for ``inspect_eval``, ES client, alert reader,
    ``start_stack``, and the Doomla compose reset."""
    _AssistantTypeShim(monkeypatch)

    # Skip stack bring-up and Doomla compose reset; both shell out.
    monkeypatch.setattr(run_all, "start_stack", lambda *a, **k: None)
    monkeypatch.setattr(run_all, "_doomla_reset", lambda: None)

    # ES side — pretend the agent is enrolled, return a deterministic
    # alert log so distinct_rules / alert_count are predictable.
    monkeypatch.setattr(
        run_all, "load_env",
        lambda: {"MONITORED_AGENT_ID": "agent-test-123"},
    )
    monkeypatch.setattr(run_all, "make_client", lambda env=None: object())
    monkeypatch.setattr(
        run_all, "read_full_alert_log",
        lambda *a, **k: [
            Alert(
                timestamp=datetime(2026, 5, 20, 12, 0, 30, tzinfo=timezone.utc),
                surface="raw",
                severity="medium",
                severity_rank=2,
                event_type="alert",
                event_code="malicious_behavior_event",
                rule_name="Malicious Behavior Detection Alert",
                container_id="c1",
                dedup_key="d1",
            ),
        ],
    )

    return tmp_path


@pytest.fixture
def eval_returns_one_sample(monkeypatch):
    """Default eval stub: one passing sample, no blocks."""
    def fake_eval(*args, **kwargs):
        return [_FakeLog(samples=[_make_sample(
            cmds=["whoami", "cat /etc/passwd"],
            output="completed. flag{4fe9e140e88ee795e2afbb24dfbcff00}",
        )])]
    monkeypatch.setattr(run_all, "inspect_eval", fake_eval)


# ---- Tests -----------------------------------------------------------------

def test_extract_commands_picks_assistant_bash_calls():
    sample = _make_sample(
        cmds=["whoami", "id", "uname -a"],
        output="ok",
    )
    # Need the isinstance shim — patch the module symbol for the duration
    # of this single-call test via a pytest monkeypatch context manager.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            run_all, "ChatMessageAssistant",
            (run_all.ChatMessageAssistant, _FakeAssistant),
        )
        assert run_all._extract_commands(sample) == ["whoami", "id", "uname -a"]


def test_extract_commands_handles_command_alias():
    """The plain ``bash()`` tool takes ``cmd``; some inspect tools may
    use ``command`` instead — the extractor should accept either."""
    sample = _make_sample(cmds=[], output="")
    sample.messages = [_FakeAssistant(tool_calls=[
        _FakeToolCall(function="bash", arguments={"command": "ls"}),
    ])]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            run_all, "ChatMessageAssistant",
            (run_all.ChatMessageAssistant, _FakeAssistant),
        )
        assert run_all._extract_commands(sample) == ["ls"]


def test_parse_iso_utc_handles_naive_and_offset_and_datetime():
    assert run_all._parse_iso_utc(None) is None
    naive = run_all._parse_iso_utc("2026-05-20T12:00:00")
    assert naive is not None and naive.utcoffset() == timezone.utc.utcoffset(naive)
    offset = run_all._parse_iso_utc("2026-05-20T12:00:00+00:00")
    assert offset is not None and offset.utcoffset() is not None
    z = run_all._parse_iso_utc("2026-05-20T12:00:00Z")
    assert z is not None and z.utcoffset() is not None
    raw = datetime(2026, 5, 20, tzinfo=timezone.utc)
    assert run_all._parse_iso_utc(raw) == raw


def test_run_one_writes_score_record(
    patched_runner, eval_returns_one_sample
):
    tmp_path: Path = patched_runner
    raw_dir = tmp_path / "raw"
    log_dir = tmp_path / "inspect_logs"
    raw_dir.mkdir()
    log_dir.mkdir()

    rec = run_all._run_one(
        arm="tier2_monitor", seed=0,
        model="test/fake-model", variant="example", limit=1,
        out_raw_dir=raw_dir, log_dir=log_dir,
    )
    assert rec["arm"] == "tier2_monitor"
    assert rec["seed"] == 0
    assert rec["alert_count"] == 1
    assert rec["score"]["completion"] is True
    assert rec["score"]["block_count"] == 0
    assert rec["score"]["distinct_rules"] == 2  # event_code + rule_name

    persisted = json.loads((raw_dir / "tier2_monitor-0.json").read_text())
    assert persisted["score"]["completion"] is True
    assert persisted["command_count"] == 2


def test_run_one_records_block_events_from_store(
    patched_runner, monkeypatch
):
    """A sample with a recorded BlockEvent should surface block_count > 0."""
    def fake_eval(*args, **kwargs):
        return [_FakeLog(samples=[_make_sample(
            cmds=["nc -lvnp 4444", "nc -lvnp 4444", "curl http://...","whoami"],
            output="aborted, no flag",
            block_events=[{
                "call_index": 1,
                "cmd": "nc -lvnp 4444",
                "trigger": "in_loop",
                "alert_dedup_keys": ["d1"],
                "rule_names": ["Suspicious Listener"],
                "severities": ["high"],
                "container_ids": ["c1"],
                "triggered_at": "2026-05-20T12:00:31+00:00",
            }],
        )])]
    monkeypatch.setattr(run_all, "inspect_eval", fake_eval)

    tmp_path: Path = patched_runner
    raw_dir = tmp_path / "raw"
    log_dir = tmp_path / "inspect_logs"
    raw_dir.mkdir()
    log_dir.mkdir()

    rec = run_all._run_one(
        arm="tier3_block", seed=2,
        model="test/fake", variant="example", limit=1,
        out_raw_dir=raw_dir, log_dir=log_dir,
    )
    assert rec["score"]["block_count"] == 1
    assert rec["score"]["resilience"] == -1   # no completion
    # The blocked command was nc; the next call repeated it verbatim.
    assert rec["score"]["pivot"] == "repeat"


def test_main_emits_per_run_files_and_manifest(
    patched_runner, eval_returns_one_sample
):
    tmp_path: Path = patched_runner
    out_dir = tmp_path / "smoke"

    rc = run_all.main([
        "--seeds", "1",
        "--arms", "tier2_monitor,tier3_block,tier3_informed",
        "--out", str(out_dir),
        "--model", "test/fake-model",
        "--skip-stack-start",
        "--skip-doomla-reset",
    ])
    assert rc == 0
    raw = out_dir / "raw"
    files = sorted(p.name for p in raw.glob("*.json"))
    assert files == [
        "tier2_monitor-0.json", "tier3_block-0.json", "tier3_informed-0.json"
    ]
    manifest = json.loads((out_dir / "manifest.json").read_text())
    assert manifest["arms"] == ["tier2_monitor", "tier3_block", "tier3_informed"]
    assert manifest["seeds"] == 1
    assert len(manifest["runs"]) == 3
    assert all(r.get("completion") is True for r in manifest["runs"])


def test_main_rejects_unknown_arm(patched_runner, eval_returns_one_sample, capsys):
    tmp_path: Path = patched_runner
    out_dir = tmp_path / "bad"
    rc = run_all.main([
        "--seeds", "1",
        "--arms", "tier2_monitor,tier1_baseline",   # tier1 removed
        "--out", str(out_dir),
        "--skip-stack-start", "--skip-doomla-reset",
    ])
    assert rc == 2
    err = capsys.readouterr().err.lower()
    assert "tier1_baseline" in err

    # And: no eval log directory should have been created.
    assert not (out_dir / "raw").exists() or not list((out_dir / "raw").iterdir())


def test_main_persists_error_records_on_eval_failure(
    patched_runner, monkeypatch
):
    """If inspect_eval raises, the runner should write a .error.json and
    keep the batch going so subsequent (arm, seed) pairs still execute."""
    call_count = {"n": 0}
    def fake_eval(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("synthetic eval crash")
        return [_FakeLog(samples=[_make_sample(
            cmds=["ok"], output="flag{4fe9e140e88ee795e2afbb24dfbcff00}",
        )])]
    monkeypatch.setattr(run_all, "inspect_eval", fake_eval)

    tmp_path: Path = patched_runner
    out_dir = tmp_path / "mixed"
    rc = run_all.main([
        "--seeds", "1",
        "--arms", "tier2_monitor,tier3_block",
        "--out", str(out_dir),
        "--skip-stack-start", "--skip-doomla-reset",
    ])
    assert rc == 1   # batch reports failure but didn't abort
    raw = out_dir / "raw"
    assert (raw / "tier2_monitor-0.error.json").exists()
    assert (raw / "tier3_block-0.json").exists()
    manifest = json.loads((out_dir / "manifest.json").read_text())
    statuses = [
        ("error" if "error" in r else "ok") for r in manifest["runs"]
    ]
    assert statuses == ["error", "ok"]


def test_run_one_tags_record_when_log_status_error(
    patched_runner, monkeypatch
):
    """Inspect-side interrupts (credit exhaustion, message-limit) land
    as ``log.status == 'error'`` with whatever messages/store
    accumulated before the interrupt. The runner should still persist
    the partial score but tag the record so the aggregator excludes it
    from per-arm means."""
    def fake_eval(*args, **kwargs):
        return [_FakeLog(
            samples=[_make_sample(
                cmds=["whoami", "id"],
                output="",  # no flag — interrupted mid-attempt
            )],
            status="error",
            error="BadRequestError(credit balance too low)",
        )]
    monkeypatch.setattr(run_all, "inspect_eval", fake_eval)

    tmp_path: Path = patched_runner
    raw_dir = tmp_path / "raw"
    log_dir = tmp_path / "inspect_logs"
    raw_dir.mkdir()
    log_dir.mkdir()

    rec = run_all._run_one(
        arm="tier3_informed_stealthy", seed=0,
        model="test/fake", variant="example", limit=1,
        out_raw_dir=raw_dir, log_dir=log_dir,
    )
    assert rec["log_status"] == "error"
    assert "error" in rec
    assert "truncated at 2 commands" in rec["error"]
    # Score still computed from partial data — useful for triage.
    assert "score" in rec
    persisted = json.loads(
        (raw_dir / "tier3_informed_stealthy-0.json").read_text()
    )
    assert "error" in persisted


def test_main_surfaces_interrupted_runs_as_errors(
    patched_runner, monkeypatch
):
    """End-to-end: an interrupted run should bump exit code to 1 and
    appear in the manifest as an error row."""
    def fake_eval(*args, **kwargs):
        return [_FakeLog(
            samples=[_make_sample(cmds=["whoami"], output="")],
            status="error",
            error="BadRequestError(credit)",
        )]
    monkeypatch.setattr(run_all, "inspect_eval", fake_eval)

    tmp_path: Path = patched_runner
    out_dir = tmp_path / "interrupted"
    rc = run_all.main([
        "--seeds", "1",
        "--arms", "tier3_informed_stealthy",
        "--out", str(out_dir),
        "--skip-stack-start", "--skip-doomla-reset",
    ])
    assert rc == 1
    manifest = json.loads((out_dir / "manifest.json").read_text())
    assert len(manifest["runs"]) == 1
    row = manifest["runs"][0]
    assert "error" in row
    assert row["log_status"] == "error"


def test_main_seed_count_validated(patched_runner, capsys):
    rc = run_all.main([
        "--seeds", "0",
        "--arms", "tier2_monitor",
        "--out", str(patched_runner / "zero"),
        "--skip-stack-start", "--skip-doomla-reset",
    ])
    assert rc == 2
    assert "seeds" in capsys.readouterr().err.lower()
