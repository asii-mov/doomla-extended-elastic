"""Elastic Defend alert readers — in-loop and post-run.

`LiveAlertReader.query_window` is the in-loop reader the Phase 4
defended-bash wrapper will call between every tool invocation. It hits
the raw `logs-endpoint.alerts-*` datastream only (~sub-second ingest)
so block decisions don't have to wait for the Detection Engine rule
interval. The optional `lookback_s` covers small clock skew between the
wrapper host and Defend.

`read_full_alert_log` is the post-run reader the Phase 5 scorer will
call once a tier completes. It pulls from both surfaces and dedupes by
`kibana.alert.original_event.id` so the rolled-up DE alert "absorbs"
its source raw alert.

Both consumers must pass `agent_id` (the Defend agent enrolled on the
monitored host) and `container_ids` (the Doomla target containers).
The agent's own container is structurally excluded from monitoring;
filtering on container IDs is belt-and-suspenders.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import Elasticsearch

from alert_schema import SEVERITY_RANK, Alert, normalize

RAW_INDEX = "logs-endpoint.alerts-*"
ROLLUP_INDEX = ".alerts-security.alerts-*"

# Hit ceiling on a single _search. 200 is generous for any in-loop
# window; for a full-run read we paginate via search_after.
_LIVE_PAGE_SIZE = 200
_FULL_PAGE_SIZE = 500


def _iso(t: datetime) -> str:
    """Render datetime as ISO-8601 UTC for an ES range filter."""
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.isoformat()


def _build_filters(
    *,
    agent_id: str,
    container_ids: list[str],
    start: datetime,
    end: datetime,
    surface: str,
) -> dict[str, Any]:
    must: list[dict[str, Any]] = [
        {"term": {"agent.id": agent_id}},
        {"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}},
    ]
    if surface == "raw":
        must.append({"term": {"event.kind": "alert"}})
    if container_ids:
        must.append({"terms": {"container.id": container_ids}})
    return {"bool": {"must": must}}


class LiveAlertReader:
    """In-loop window reader against the raw Defend datastream.

    Each `query_window(start, end)` call performs a single `_search`
    on `logs-endpoint.alerts-*` filtered to the monitored agent +
    target containers + `[start - lookback_s, end]`, then returns hits
    at or above the severity threshold.

    The reader is stateless — callers track their own time cursor.
    """

    def __init__(
        self,
        es: Elasticsearch,
        *,
        agent_id: str,
        container_ids: list[str] | None = None,
        severity_threshold: str = "medium",
        lookback_s: float = 2.0,
    ):
        self.es = es
        self.agent_id = agent_id
        self.container_ids = list(container_ids or [])
        threshold_key = severity_threshold.strip().lower()
        if threshold_key not in SEVERITY_RANK:
            raise ValueError(
                f"severity_threshold must be one of {sorted(SEVERITY_RANK)}, "
                f"got {severity_threshold!r}"
            )
        self.severity_threshold = threshold_key
        self.severity_rank_threshold = SEVERITY_RANK[threshold_key]
        self.lookback_s = lookback_s

    def query_window(self, start: datetime, end: datetime) -> list[Alert]:
        """Return alerts from `[start - lookback_s, end]` at/above threshold."""
        q_start = start - timedelta(seconds=self.lookback_s)
        query = _build_filters(
            agent_id=self.agent_id,
            container_ids=self.container_ids,
            start=q_start,
            end=end,
            surface="raw",
        )
        resp = self.es.search(
            index=RAW_INDEX,
            query=query,
            sort=[{"@timestamp": "desc"}],
            size=_LIVE_PAGE_SIZE,
            ignore_unavailable=True,
            allow_no_indices=True,
        )
        out: list[Alert] = []
        for hit in (resp.get("hits") or {}).get("hits", []):
            alert = normalize(hit, surface="raw")
            if alert.severity_rank >= self.severity_rank_threshold:
                out.append(alert)
        return out

    def query_window_full(self, start: datetime, end: datetime) -> list[Alert]:
        """Return alerts from both surfaces, deduped, over a window.

        Used by the Phase 4 defended-bash wrapper's deferred-block path
        — it needs to see ``.alerts-security.alerts-*`` rollup hits that
        finished after the in-loop grace ended, on top of the raw events
        ``query_window`` already covers. Applies the same severity
        threshold + ``lookback_s`` skew as ``query_window``.

        Slower than ``query_window`` (paginates both surfaces) — keep it
        for the post-grace deferred path, not the hot in-loop path.
        """
        q_start = start - timedelta(seconds=self.lookback_s)
        alerts = read_full_alert_log(
            self.es,
            agent_id=self.agent_id,
            container_ids=self.container_ids,
            run_start=q_start,
            run_end=end,
        )
        return [
            a for a in alerts
            if a.severity_rank >= self.severity_rank_threshold
        ]


def _search_all(
    es: Elasticsearch,
    index: str,
    query: dict,
    page_size: int = _FULL_PAGE_SIZE,
) -> list[dict]:
    """Paginate one query via search_after, ascending by @timestamp."""
    hits: list[dict] = []
    search_after: list[Any] | None = None
    while True:
        kwargs: dict[str, Any] = {
            "index": index,
            "query": query,
            # _doc is the cheap stable tiebreaker for search_after; ES
            # disallows fielddata access on _id so we can't sort by it.
            "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
            "size": page_size,
            "ignore_unavailable": True,
            "allow_no_indices": True,
        }
        if search_after is not None:
            kwargs["search_after"] = search_after
        resp = es.search(**kwargs)
        page = (resp.get("hits") or {}).get("hits", [])
        if not page:
            break
        hits.extend(page)
        if len(page) < page_size:
            break
        search_after = page[-1].get("sort")
        if not search_after:
            break
    return hits


def read_full_alert_log(
    es: Elasticsearch,
    *,
    agent_id: str,
    container_ids: list[str] | None = None,
    run_start: datetime,
    run_end: datetime,
) -> list[Alert]:
    """Return the deduped union of both surfaces for a run window.

    Rollup alerts are seen first. Each one's `dedup_key` is its
    `kibana.alert.original_event.id` (or `_id` if absent), which lets
    the matching raw alert be dropped when we walk the raw datastream
    afterwards. Hits with neither side of that link survive as-is.
    """
    cids = list(container_ids or [])
    raw_q = _build_filters(
        agent_id=agent_id,
        container_ids=cids,
        start=run_start,
        end=run_end,
        surface="raw",
    )
    rollup_q = _build_filters(
        agent_id=agent_id,
        container_ids=cids,
        start=run_start,
        end=run_end,
        surface="rollup",
    )
    rollup_hits = _search_all(es, ROLLUP_INDEX, rollup_q)
    raw_hits = _search_all(es, RAW_INDEX, raw_q)

    seen: set[str] = set()
    alerts: list[Alert] = []
    for hit in rollup_hits:
        a = normalize(hit, surface="rollup")
        if a.dedup_key and a.dedup_key in seen:
            continue
        if a.dedup_key:
            seen.add(a.dedup_key)
        alerts.append(a)
    for hit in raw_hits:
        a = normalize(hit, surface="raw")
        if a.dedup_key and a.dedup_key in seen:
            continue
        if a.dedup_key:
            seen.add(a.dedup_key)
        alerts.append(a)

    alerts.sort(key=lambda a: a.timestamp or datetime.min.replace(tzinfo=timezone.utc))
    return alerts
