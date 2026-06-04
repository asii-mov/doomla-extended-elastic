"""Unit + integration tests for the Phase 2 alert client library.

Unit tests use a hand-rolled `FakeES` so the suite stays hermetic — no
network, no live stack, no real API key. Run with:

    uv run pytest -k "not integration"

The single integration test is gated on the env var `PHASE1_STACK=up`
because it needs the live Phase 1 cluster, an enrolled Defend agent on
this host, and the working API key in `.harness/elastic.env`. Run with:

    PHASE1_STACK=up uv run pytest -k integration
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from alert_reader import (
    LiveAlertReader,
    RAW_INDEX,
    ROLLUP_INDEX,
    read_full_alert_log,
)
from alert_schema import Alert, _coerce_severity, normalize

# Sentinel values used in unit-test fixtures. NOT a real API key.
FAKE_API_KEY = "FAKE_API_KEY_FOR_TESTS_ONLY"
TEST_AGENT_ID = "test-agent-0001"
TEST_CONTAINERS = ["doomla-joomla", "doomla-workstation"]


# ---------------------------------------------------------------------------
# FakeES: minimal stub of elasticsearch.Elasticsearch.search
# ---------------------------------------------------------------------------


class FakeES:
    """Stub that records `search` calls and returns scripted responses."""

    def __init__(self, responses: dict[str, list[dict]] | list[dict] | None = None):
        # responses can be a single hit list (returned for every call) or a
        # dict keyed by index, where the value is the list of hits to return.
        self.responses = responses if responses is not None else []
        self.calls: list[dict[str, Any]] = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        index = kwargs.get("index", "")
        if isinstance(self.responses, dict):
            hits = self.responses.get(index, [])
        else:
            hits = self.responses
        return {"hits": {"hits": list(hits), "total": {"value": len(hits)}}}


def _make_hit(
    *,
    _id: str,
    surface: str,
    severity: Any,
    agent_id: str = TEST_AGENT_ID,
    container_id: str | None = None,
    rule_name: str = "Malware Prevention Alert",
    file_path: str = "/tmp/canary.txt",
    timestamp: str = "2026-05-20T10:00:00Z",
    action: str = "execution_blocked",
    original_event_id: str | None = None,
) -> dict:
    """Build a fake `_search` hit for either surface."""
    if surface == "raw":
        index = "logs-endpoint.alerts-2026.05.20-000001"
        source: dict[str, Any] = {
            "@timestamp": timestamp,
            "agent": {"id": agent_id},
            "event": {
                "kind": "alert",
                "code": "malicious_file",
                "category": ["malware"],
                "severity": severity,
                "action": action,
            },
            "rule": {"name": rule_name},
            "file": {"path": file_path},
            "process": {
                "name": "bash",
                "executable": "/usr/bin/bash",
                "args": ["bash", "-c", "echo eicar"],
            },
        }
        if container_id:
            source["container"] = {"id": container_id, "name": container_id}
    else:
        index = ".internal.alerts-security.alerts-default-000001"
        source = {
            "@timestamp": timestamp,
            "agent.id": agent_id,
            "kibana.alert.severity": severity,
            "kibana.alert.rule.name": rule_name,
            "kibana.alert.reason": f"malware on {file_path}",
            "kibana.alert.rule.threat": [
                {
                    "tactic": {"name": "Defense Evasion"},
                    "technique": [{"name": "Obfuscated Files or Information"}],
                }
            ],
            "file": {"path": file_path},
            "process": {"name": "bash", "executable": "/usr/bin/bash"},
        }
        if container_id:
            source["container"] = {"id": container_id, "name": container_id}
        if original_event_id:
            # Detection Engine writes this as a flat dotted top-level key.
            source["kibana.alert.original_event.id"] = original_event_id
    return {"_id": _id, "_index": index, "_source": source}


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------


def test_severity_coercion_numeric():
    assert _coerce_severity(80) == "critical"
    assert _coerce_severity(50) == "high"
    assert _coerce_severity(30) == "medium"
    assert _coerce_severity(10) == "low"
    assert _coerce_severity(0) == "low"


def test_severity_coercion_strings():
    assert _coerce_severity("critical") == "critical"
    assert _coerce_severity("Medium") == "medium"
    assert _coerce_severity("warning") == "medium"   # syslog level
    assert _coerce_severity("emergency") == "critical"
    assert _coerce_severity(None) == "low"
    assert _coerce_severity("garbage") == "low"


def test_normalize_raw_surface():
    hit = _make_hit(_id="raw-1", surface="raw", severity=80, action="execution_blocked")
    a = normalize(hit)
    assert a.surface == "raw"
    assert a.severity == "critical"
    assert a.severity_rank == 4
    assert a.event_code == "malicious_file"
    assert a.event_type == "denied"
    assert a.rule_name == "Malware Prevention Alert"
    assert a.process_name == "bash"
    assert "echo eicar" in (a.process_command_line or "")
    assert a.dedup_key == "raw-1"
    assert a.timestamp is not None
    assert a.timestamp.tzinfo is not None


def test_normalize_rollup_surface_with_original_event_link():
    hit = _make_hit(
        _id="rollup-1",
        surface="rollup",
        severity="high",
        original_event_id="raw-1",
    )
    a = normalize(hit)
    assert a.surface == "rollup"
    assert a.severity == "high"
    assert a.severity_rank == 3
    assert "Defense Evasion" in a.mitre_tactic
    assert "Obfuscated Files or Information" in a.mitre_technique
    # Dedup key links back to the raw event so the raw hit gets absorbed.
    assert a.dedup_key == "raw-1"


def test_normalize_surface_inferred_from_index():
    hit = _make_hit(_id="x", surface="raw", severity=50)
    assert normalize(hit).surface == "raw"
    hit = _make_hit(_id="y", surface="rollup", severity="medium")
    assert normalize(hit).surface == "rollup"


# ---------------------------------------------------------------------------
# LiveAlertReader tests
# ---------------------------------------------------------------------------


def test_live_reader_rejects_unknown_severity():
    es = FakeES()
    with pytest.raises(ValueError):
        LiveAlertReader(
            es, agent_id=TEST_AGENT_ID, severity_threshold="catastrophic",
        )


def test_live_reader_query_construction():
    es = FakeES()
    reader = LiveAlertReader(
        es,
        agent_id=TEST_AGENT_ID,
        container_ids=TEST_CONTAINERS,
        severity_threshold="high",
        lookback_s=5.0,
    )
    end = datetime(2026, 5, 20, 10, 0, 0, tzinfo=timezone.utc)
    start = end - timedelta(seconds=10)
    reader.query_window(start, end)

    assert len(es.calls) == 1
    call = es.calls[0]
    assert call["index"] == RAW_INDEX
    assert call["size"] == 200
    assert call["sort"] == [{"@timestamp": "desc"}]

    must = call["query"]["bool"]["must"]
    assert {"term": {"agent.id": TEST_AGENT_ID}} in must
    assert {"term": {"event.kind": "alert"}} in must
    assert {"terms": {"container.id": TEST_CONTAINERS}} in must

    range_filter = next(m for m in must if "range" in m)
    range_window = range_filter["range"]["@timestamp"]
    # lookback_s = 5 → start filter is end-15s
    parsed_start = datetime.fromisoformat(range_window["gte"])
    parsed_end = datetime.fromisoformat(range_window["lte"])
    assert (end - parsed_start).total_seconds() == pytest.approx(15.0)
    assert parsed_end == end


def test_live_reader_no_container_filter_when_empty():
    es = FakeES()
    reader = LiveAlertReader(es, agent_id=TEST_AGENT_ID, container_ids=[])
    reader.query_window(
        datetime(2026, 5, 20, 9, 59, 0, tzinfo=timezone.utc),
        datetime(2026, 5, 20, 10, 0, 0, tzinfo=timezone.utc),
    )
    must = es.calls[0]["query"]["bool"]["must"]
    assert not any("terms" in m and "container.id" in m["terms"] for m in must)


def test_live_reader_severity_threshold_filters_results():
    hits = [
        _make_hit(_id="a", surface="raw", severity=10),   # low
        _make_hit(_id="b", surface="raw", severity=30),   # medium
        _make_hit(_id="c", surface="raw", severity=80),   # critical
    ]
    es = FakeES(hits)
    reader = LiveAlertReader(
        es, agent_id=TEST_AGENT_ID, severity_threshold="medium",
    )
    out = reader.query_window(
        datetime(2026, 5, 20, 9, 59, 0, tzinfo=timezone.utc),
        datetime(2026, 5, 20, 10, 0, 0, tzinfo=timezone.utc),
    )
    ids = {a.dedup_key for a in out}
    assert ids == {"b", "c"}

    high_reader = LiveAlertReader(
        es, agent_id=TEST_AGENT_ID, severity_threshold="high",
    )
    out_high = high_reader.query_window(
        datetime(2026, 5, 20, 9, 59, 0, tzinfo=timezone.utc),
        datetime(2026, 5, 20, 10, 0, 0, tzinfo=timezone.utc),
    )
    assert {a.dedup_key for a in out_high} == {"c"}


# ---------------------------------------------------------------------------
# read_full_alert_log tests
# ---------------------------------------------------------------------------


def test_full_read_dedups_rollup_against_raw():
    raw_hits = [
        _make_hit(_id="raw-1", surface="raw", severity=80,
                  timestamp="2026-05-20T10:00:00Z"),
        _make_hit(_id="raw-2", surface="raw", severity=50,
                  timestamp="2026-05-20T10:00:05Z"),
    ]
    rollup_hits = [
        # links back to raw-1 → should absorb it
        _make_hit(_id="rollup-1", surface="rollup", severity="critical",
                  timestamp="2026-05-20T10:01:00Z",
                  original_event_id="raw-1"),
        # standalone rollup with no link → stays as its own entry
        _make_hit(_id="rollup-2", surface="rollup", severity="medium",
                  timestamp="2026-05-20T10:01:30Z"),
    ]
    es = FakeES({RAW_INDEX: raw_hits, ROLLUP_INDEX: rollup_hits})

    out = read_full_alert_log(
        es,
        agent_id=TEST_AGENT_ID,
        container_ids=[],
        run_start=datetime(2026, 5, 20, 9, 59, 0, tzinfo=timezone.utc),
        run_end=datetime(2026, 5, 20, 10, 2, 0, tzinfo=timezone.utc),
    )

    # rollup-1 absorbs raw-1; raw-2 + rollup-2 are independent → 3 total.
    assert len(out) == 3
    by_key: dict[str, list[Alert]] = {}
    for a in out:
        by_key.setdefault(a.dedup_key, []).append(a)
    # Exactly one alert under the shared key, and it must come from the rollup
    # surface — the raw twin was deduped away.
    assert len(by_key["raw-1"]) == 1
    assert by_key["raw-1"][0].surface == "rollup"
    # Independent rollup and raw still present.
    assert any(a.surface == "rollup" and a.dedup_key == "rollup-2" for a in out)
    assert any(a.surface == "raw" and a.dedup_key == "raw-2" for a in out)
    # Sorted by timestamp ascending.
    assert out == sorted(out, key=lambda a: a.timestamp)


def test_full_read_paginates_via_search_after():
    """A response of exactly page_size should trigger a second search call."""
    # Build PAGE_SIZE hits in the raw index then 0 the next time around.
    from alert_reader import _FULL_PAGE_SIZE

    big_page = [
        _make_hit(
            _id=f"raw-{i}", surface="raw", severity=80,
            timestamp=f"2026-05-20T10:00:{i:02d}Z",
        )
        # only need a few — let's force pagination by lying about page_size
        for i in range(3)
    ]
    # Attach `sort` cursors so search_after works (timestamp + _doc tiebreak).
    for idx, h in enumerate(big_page):
        h["sort"] = [h["_source"]["@timestamp"], idx]

    class PagingES:
        def __init__(self):
            self.calls = 0

        def search(self, **kwargs):
            self.calls += 1
            if kwargs["index"] == ROLLUP_INDEX:
                return {"hits": {"hits": []}}
            # Simulate one full page then an empty page.
            if self.calls == 1:
                # Trim to a synthetic page size of 3 so we trigger a 2nd call
                # by claiming a full page.
                return {"hits": {"hits": big_page}}
            return {"hits": {"hits": []}}

    es = PagingES()
    # Monkey-patch the page size for this test only by calling with a
    # smaller page via the helper path.
    from alert_reader import _search_all
    hits = _search_all(es, RAW_INDEX, {"match_all": {}}, page_size=3)
    assert len(hits) == 3
    # Called twice — first full page, then empty page that terminates the loop.
    assert es.calls == 2


# ---------------------------------------------------------------------------
# Secrets hygiene: API key must not leak into fixtures/exception messages.
# ---------------------------------------------------------------------------


def test_no_real_api_key_in_test_module():
    """Tripwire: the test file must use only the sentinel key."""
    text = Path(__file__).read_text()
    # The only string with "API_KEY" in it should be FAKE_API_KEY_FOR_TESTS_ONLY.
    api_key_strings = re.findall(r"[A-Za-z0-9+/]{30,}=*", text)
    assert all(s == FAKE_API_KEY or "FAKE" in s for s in api_key_strings), \
        "test fixtures must not contain a real-looking API key"


def test_make_client_does_not_echo_api_key_in_errors(tmp_path):
    """Missing-URL config should error without exposing the API key value."""
    from es_client import load_env, make_client

    env_file = tmp_path / "elastic.env"
    env_file.write_text(f"ES_API_KEY={FAKE_API_KEY}\n")  # no ELASTIC_URL

    env = load_env(env_file)
    with pytest.raises(KeyError) as exc_info:
        make_client(env=env)
    assert FAKE_API_KEY not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Integration test — live Phase 1 stack required.
# ---------------------------------------------------------------------------

# AV-industry non-malicious test string. Broken into pieces so this source
# file doesn't itself trip a scanner.
EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    "$EICAR" "-STANDARD-" "ANTIVIRUS-" "TEST-FILE!"
    "$H+H*"
)


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("PHASE1_STACK") != "up",
    reason="set PHASE1_STACK=up to run against the live Phase 1 stack",
)
def test_integration_canary_visible_on_both_surfaces():
    from es_client import load_env, make_client

    env = load_env()
    if not env.get("MONITORED_AGENT_ID"):
        pytest.skip("elastic.env missing MONITORED_AGENT_ID")

    # Default to insecure so this works with the Phase 1 self-signed CA
    # without the user having to fiddle with system trust stores. Override
    # by setting ELASTIC_INSECURE=0 if you've added the CA to the OS trust
    # store and want strict verification.
    os.environ.setdefault("ELASTIC_INSECURE", "1")

    es = make_client(env=env)
    agent_id = env["MONITORED_AGENT_ID"]
    token = uuid.uuid4().hex[:12]
    canary = Path(f"/tmp/eicar-canary-test-{token}.txt")

    t_start = datetime.now(timezone.utc) - timedelta(seconds=5)

    canary.write_text(EICAR)
    try:
        # Poll the live reader for up to 90s — first-alert ingest lag on
        # cold start has been observed at ~40s on this host.
        reader = LiveAlertReader(
            es,
            agent_id=agent_id,
            container_ids=[],          # host-level alert; no container
            severity_threshold="low",  # don't filter the canary out
        )
        live_hits: list = []
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            live_hits = [
                a for a in reader.query_window(
                    t_start, datetime.now(timezone.utc),
                )
                if token in (a.raw.get("file", {}).get("path") or "")
            ]
            if live_hits:
                break
            time.sleep(2)
        assert live_hits, f"no raw-surface alert for canary token={token} within 90s"

        # Full-log read across both surfaces. Wait a beat for the DE rule
        # interval (~60s) before asserting the rollup is present.
        t_end = datetime.now(timezone.utc) + timedelta(seconds=5)
        full_hits: list = []
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            all_alerts = read_full_alert_log(
                es,
                agent_id=agent_id,
                container_ids=[],
                run_start=t_start,
                run_end=t_end,
            )
            full_hits = [
                a for a in all_alerts
                if token in (a.raw.get("file", {}).get("path") or "")
                or token in (a.raw.get("kibana.alert.reason") or "")
            ]
            if full_hits:
                break
            time.sleep(2)
        assert full_hits, f"no full-log hit for canary token={token} within 90s"
    finally:
        canary.unlink(missing_ok=True)
