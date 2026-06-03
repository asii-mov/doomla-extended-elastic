"""Stack control for the elastic compose profile (Tiers 2/3).

Brings up Elasticsearch + Kibana + Fleet Server via docker compose, then
waits for the host-installed Defend agent to register as Healthy in
Fleet. Stdlib HTTP only — no new transitive deps.

Phase 7 owns the broader stack lifecycle (start once before a batch,
stop after); Phase 3 only needs ``start_stack`` for the per-task pre-step
and ``stop_stack`` as an opt-in cleanup that Phase 7 can drive.
"""

from __future__ import annotations

import atexit
import base64
import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from es_client import load_env

REPO_ROOT = Path(__file__).resolve().parent
COMPOSE_FILE = REPO_ROOT / "compose.elastic.yaml"


def _ssl_context(env: dict[str, str]) -> ssl.SSLContext:
    if os.environ.get("ELASTIC_INSECURE") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ca = env.get("ELASTIC_CA_CERT_PATH")
    if ca and Path(ca).exists():
        ctx = ssl.create_default_context(cafile=ca)
    else:
        ctx = ssl.create_default_context()
    # Cert SAN covers localhost / service DNS; we connect via 127.0.0.1,
    # so trust the CA pin and skip the hostname check.
    ctx.check_hostname = False
    return ctx


def _kibana_get(env: dict[str, str], path: str, timeout: float = 10.0):
    user = env["ELASTIC_USERNAME"]
    pw = env["ELASTIC_PASSWORD"]
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(
        env["KIBANA_URL"] + path,
        headers={
            "Authorization": auth,
            "Accept": "application/json",
            "kbn-xsrf": "edr-elastic-task",
        },
        method="GET",
    )
    with urllib.request.urlopen(
        req, context=_ssl_context(env), timeout=timeout
    ) as r:
        return json.loads(r.read())


def _wait_defend_agent(env: dict[str, str], timeout_s: int) -> None:
    agent_id = env.get("MONITORED_AGENT_ID")
    if not agent_id:
        # Phase 1 may have completed before the operator enrolled the
        # agent. Don't block; downstream phases will error loudly if the
        # alert stream is empty.
        return

    deadline = time.monotonic() + timeout_s
    last = "no response yet"
    while time.monotonic() < deadline:
        try:
            payload = _kibana_get(env, f"/api/fleet/agents/{agent_id}")
            status = (payload.get("item") or {}).get("status")
            if status in ("online", "healthy"):
                return
            last = f"status={status!r}"
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError) as exc:
            last = repr(exc)
        time.sleep(3)
    raise RuntimeError(
        f"Defend agent {agent_id} did not become Healthy within "
        f"{timeout_s}s (last: {last})"
    )


# Services we need fully healthy before the eval starts. The one-shot
# ``setup`` container is dragged in by depends_on and exits 0 once certs
# exist; ``docker compose --wait`` can't represent that, so we skip it
# and poll the long-running services ourselves.
SERVICES_TO_WAIT_FOR = ("elasticsearch", "kibana", "fleet-server")


def _services_healthy(services: tuple[str, ...]) -> bool:
    """Return True when every named service has a healthy running container."""
    proc_env = {**os.environ, "COMPOSE_PROFILES": "elastic"}
    out = subprocess.run(
        [
            "docker", "compose", "-f", str(COMPOSE_FILE),
            "ps", "--format", "json", *services,
        ],
        check=True,
        capture_output=True,
        text=True,
        env=proc_env,
    ).stdout
    seen: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        seen[row.get("Service", "")] = row.get("Health", "")
    return all(seen.get(s) == "healthy" for s in services)


def _wait_services_healthy(timeout_s: int) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _services_healthy(SERVICES_TO_WAIT_FOR):
            return
        time.sleep(3)
    raise RuntimeError(
        f"Stack services {SERVICES_TO_WAIT_FOR} did not all become healthy "
        f"within {timeout_s}s"
    )


def start_stack(
    *, stack_timeout_s: int = 180, agent_timeout_s: int = 180
) -> None:
    """Bring up the elastic compose profile and wait for Defend healthy.

    Phase 1's ``setup_elastic.py`` is the cold bring-up: it provisions
    certs/volumes and enrolls the Defend agent. Phase 3 assumes that's
    already happened, so we bring the long-running services up with
    ``--no-deps``. Without it, compose re-evaluates the one-shot
    ``setup`` container's healthcheck on every call and fails on its
    clean exit (no health record after the container is gone).
    Then we poll healthchecks ourselves and poll Fleet for the Defend
    agent.
    """
    proc_env = {**os.environ, "COMPOSE_PROFILES": "elastic"}
    subprocess.run(
        [
            "docker", "compose", "-f", str(COMPOSE_FILE),
            "up", "-d", "--no-deps",
            *SERVICES_TO_WAIT_FOR,
        ],
        check=True,
        env=proc_env,
    )
    _wait_services_healthy(stack_timeout_s)
    _wait_defend_agent(load_env(), agent_timeout_s)


def stop_stack() -> None:
    """Stop the elastic compose profile (volumes preserved)."""
    proc_env = {**os.environ, "COMPOSE_PROFILES": "elastic"}
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "stop"],
        check=True,
        env=proc_env,
    )


def register_stop_on_exit() -> None:
    """Idempotently register ``stop_stack`` as an atexit handler."""
    atexit.register(stop_stack)
