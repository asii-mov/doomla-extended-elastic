"""Unit tests for the Phase 4 defended-bash wrapper.

The Inspect runtime dependencies (``sandbox``, ``store``) and the live alert
reader are monkey-patched so the block-decision logic can be exercised in
isolation. Async ``execute`` calls are driven with ``asyncio.run`` to keep
the suite hermetic — no pytest async plugin, no live stack, no real ES.

Cases covered:

* No alert during the in-loop window AND no deferred hit on the next call
  → both calls' outputs pass through verbatim.
* An ``event.type=denied`` alert arrives during the in-loop window
  → block message returned, command output suppressed, ``BlockEvent``
  with ``trigger="in_loop"`` recorded under the previous call's index.
* No in-loop alert, but a rollup hit arrives between calls → the *next*
  call returns the block message (attributed to the previous call).
* An alert on a non-target container is dropped (defence-in-depth on top
  of Phase 1's structural exclusion).
* The block message string never names Elastic, Defend, or any vendor.
"""

from __future__ import annotations

import asyncio
import re
import sys
from datetime import datetime, timezone

from alert_schema import Alert
from defended_bash import (
    BLOCK_EVENTS_KEY,
    BLOCK_MESSAGE,
    make_defended_bash,
)

import defended_bash as defended_bash_mod


# ---------------------------------------------------------------------------
# Fakes for sandbox(), store(), and LiveAlertReader.
# ---------------------------------------------------------------------------


class FakeExecResult:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class FakeSandbox:
    def __init__(self, results):
        # Allow scripted responses across multiple calls. Last result is
        # reused if more calls than results.
        self._results = list(results)

    async def exec(self, cmd, timeout):
        if len(self._results) > 1:
            return self._results.pop(0)
        return self._results[0]


class FakeStore:
    """Minimal dict-backed stand-in for an Inspect ``Store``."""

    def __init__(self):
        self._d: dict = {}

    def get(self, key, default=None):
        return self._d.get(key, default)

    def set(self, key, value):
        self._d[key] = value


class FakeReader:
    """Drop-in for ``LiveAlertReader`` with scripted scenario batches.

    ``in_loop_batches`` is a list — popped one batch per ``query_window``
    call. ``deferred_batches`` is popped one batch per
    ``query_window_full`` call.
    """

    def __init__(self, *, in_loop_batches=None, deferred_batches=None):
        self.in_loop_batches = list(in_loop_batches or [])
        self.deferred_batches = list(deferred_batches or [])
        self.in_loop_calls: list[tuple] = []
        self.deferred_calls: list[tuple] = []

    def query_window(self, start, end):
        self.in_loop_calls.append((start, end))
        if self.in_loop_batches:
            return self.in_loop_batches.pop(0)
        return []

    def query_window_full(self, start, end):
        self.deferred_calls.append((start, end))
        if self.deferred_batches:
            return self.deferred_batches.pop(0)
        return []


async def _noop_sleep(_seconds):
    return None


def _alert(
    *,
    dedup_key="alert-1",
    rule_name="Defend test rule",
    severity="medium",
    severity_rank=2,
    event_type="denied",
    container_id="doomla-joomla",
    timestamp: datetime | None = None,
) -> Alert:
    return Alert(
        timestamp=timestamp or datetime(2026, 5, 20, 10, 0, 0, tzinfo=timezone.utc),
        surface="raw",
        severity=severity,
        severity_rank=severity_rank,
        event_type=event_type,
        event_code="malicious_file",
        rule_name=rule_name,
        container_id=container_id,
        container_name=container_id,
        process_name="bash",
        process_command_line="bash -c whoami",
        dedup_key=dedup_key,
    )


def _patch(monkeypatch, *, exec_results, store, reader):
    monkeypatch.setattr(
        defended_bash_mod, "sandbox", lambda: FakeSandbox(exec_results),
    )
    monkeypatch.setattr(defended_bash_mod, "store", lambda: store)
    monkeypatch.setattr(defended_bash_mod.asyncio, "sleep", _noop_sleep)
    return reader


def _drive(tool, cmd):
    """Run the underlying execute() coroutine to completion."""
    return asyncio.run(tool(cmd=cmd, timeout=60))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_passthrough_when_no_alerts(monkeypatch):
    """No in-loop or deferred hits → output passes through verbatim."""
    store = FakeStore()
    reader = FakeReader()
    _patch(monkeypatch, exec_results=[FakeExecResult(stdout="hello")],
           store=store, reader=reader)

    tool = make_defended_bash(reader, target_container_ids=set())
    out = _drive(tool, "echo hello")

    assert out == "hello"
    # One block-event list should not be appended.
    assert store.get(BLOCK_EVENTS_KEY) in (None, [])
    # The first call's deferred state should be saved for the next call.
    assert store.get("defended_bash_deferred_state") is not None


def test_in_loop_block_suppresses_output(monkeypatch):
    """A denied alert in the grace window → block message, output dropped."""
    store = FakeStore()
    reader = FakeReader(in_loop_batches=[[_alert(dedup_key="raw-1")]])
    _patch(monkeypatch, exec_results=[FakeExecResult(stdout="secret-leak")],
           store=store, reader=reader)

    tool = make_defended_bash(reader, target_container_ids={"doomla-joomla"})
    out = _drive(tool, "whoami")

    assert out == BLOCK_MESSAGE
    # The agent must never see the command's real output on a block.
    assert "secret-leak" not in out

    events = store.get(BLOCK_EVENTS_KEY)
    assert events is not None and len(events) == 1
    event = events[0]
    assert event["trigger"] == "in_loop"
    assert event["cmd"] == "whoami"
    assert event["call_index"] == 1
    assert event["alert_dedup_keys"] == ["raw-1"]
    assert event["rule_names"] == ["Defend test rule"]

    # Block-path returns early — the deferred state must NOT be set
    # (we already attributed a block to this call).
    assert store.get("defended_bash_deferred_state") is None


def test_deferred_block_on_next_call(monkeypatch):
    """Rolled-up alert arrives between calls → next call returns the block."""
    store = FakeStore()
    # Call 1: nothing on in-loop or deferred.
    # Call 2: deferred check finds a rollup hit (full surface) for call 1.
    reader = FakeReader(
        in_loop_batches=[[]],  # call 1 in-loop: empty
        deferred_batches=[[_alert(dedup_key="rollup-1",
                                    rule_name="Suspicious Behaviour",
                                    severity="high",
                                    severity_rank=3)]],
    )
    _patch(monkeypatch,
           exec_results=[FakeExecResult(stdout="cmd1-out"),
                         FakeExecResult(stdout="cmd2-out")],
           store=store, reader=reader)

    tool = make_defended_bash(reader, target_container_ids={"doomla-joomla"})

    out1 = _drive(tool, "id")
    assert out1 == "cmd1-out"
    # Deferred state stashed for call 2.
    assert store.get("defended_bash_deferred_state") is not None

    out2 = _drive(tool, "uname -a")
    assert out2 == BLOCK_MESSAGE

    events = store.get(BLOCK_EVENTS_KEY)
    assert events is not None and len(events) == 1
    event = events[0]
    assert event["trigger"] == "deferred"
    # Block must be attributed to the COMMAND that triggered it, not the
    # one we were about to run.
    assert event["call_index"] == 1
    assert event["cmd"] == "id"
    assert event["alert_dedup_keys"] == ["rollup-1"]

    # After a deferred block, state must be cleared so a subsequent call
    # doesn't double-fire.
    assert store.get("defended_bash_deferred_state") is None


def test_alert_on_non_target_container_is_ignored(monkeypatch):
    """Alerts outside ``target_container_ids`` must not trigger a block."""
    store = FakeStore()
    reader = FakeReader(
        # Defend reported an alert, but it's from the agent's own container —
        # we should NOT block. Defence-in-depth on top of Phase 1.
        in_loop_batches=[[_alert(dedup_key="raw-stray",
                                  container_id="doomla-kali")]],
    )
    _patch(monkeypatch, exec_results=[FakeExecResult(stdout="ok")],
           store=store, reader=reader)

    tool = make_defended_bash(reader, target_container_ids={"doomla-joomla"})
    out = _drive(tool, "ls")

    assert out == "ok"
    assert store.get(BLOCK_EVENTS_KEY) in (None, [])


def test_non_denied_alert_does_not_trigger_in_loop_block(monkeypatch):
    """In-loop check filters to event.type=denied (prevention path).

    A raw-surface alert with event.type != "denied" must NOT trigger the
    in-loop block — the deferred path picks those up on the next call.
    """
    store = FakeStore()
    reader = FakeReader(
        in_loop_batches=[[_alert(dedup_key="raw-detect-only",
                                  event_type="allowed")]],
    )
    _patch(monkeypatch, exec_results=[FakeExecResult(stdout="run")],
           store=store, reader=reader)

    tool = make_defended_bash(reader, target_container_ids={"doomla-joomla"})
    out = _drive(tool, "ls /tmp")

    assert out == "run"
    assert store.get(BLOCK_EVENTS_KEY) in (None, [])


def test_block_message_is_vendor_neutral():
    """The block message must never name the vendor or product."""
    leaking_tokens = re.compile(r"\b(elastic|defend|kibana|fleet|falco)\b",
                                  re.IGNORECASE)
    assert not leaking_tokens.search(BLOCK_MESSAGE), (
        f"BLOCK_MESSAGE leaks a vendor token: {BLOCK_MESSAGE!r}"
    )
    # And the message is non-trivial (not empty / not just whitespace).
    assert BLOCK_MESSAGE.strip()


def test_output_includes_stderr_and_exit_code(monkeypatch):
    """Non-zero exits and stderr are annotated onto the returned output."""
    store = FakeStore()
    reader = FakeReader()
    _patch(monkeypatch,
           exec_results=[FakeExecResult(stdout="out", stderr="err",
                                          returncode=2)],
           store=store, reader=reader)

    tool = make_defended_bash(reader, target_container_ids=set())
    out = _drive(tool, "false")

    assert out == "out\n[stderr]\nerr\n[exit code: 2]"


def test_call_counter_increments(monkeypatch):
    """Per-sample call index increments across calls."""
    store = FakeStore()
    reader = FakeReader()
    _patch(monkeypatch,
           exec_results=[FakeExecResult(stdout="a"),
                          FakeExecResult(stdout="b"),
                          FakeExecResult(stdout="c")],
           store=store, reader=reader)

    tool = make_defended_bash(reader, target_container_ids=set())
    _drive(tool, "echo a")
    _drive(tool, "echo b")
    _drive(tool, "echo c")

    assert store.get("defended_bash_call_counter") == 3
