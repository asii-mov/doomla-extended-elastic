#!/usr/bin/env python3
"""
Phase 1 idempotent setup driver for the Elastic Stack + Defend bring-up.

Run after:
    COMPOSE_PROFILES=elastic docker compose -f compose.elastic.yaml up -d setup elasticsearch kibana

Steps (idempotent):
    1. Extract CA cert from docker volume to .harness/elastic-ca.crt
    2. Wait for Elasticsearch yellow/green
    3. Start Enterprise trial license (no-op if already trial)
    4. Wait for Kibana available
    5. POST /api/fleet/setup
    6. Create Fleet Server agent policy (has_fleet_server=true → auto integration)
    7. Mint Fleet Server service token
    8. Create empty Defend agent policy (operator adds Endpoint integration via UI)
    9. Install + enable Prebuilt Detection Rules library
   10. Mint Phase 2 alert-reader API key
   11. Discover monitored agent ID (if Defend agent already enrolled)
   12. Write .harness/elastic.env

Then operator brings up Fleet Server:
    docker compose -f compose.elastic.yaml --profile elastic up -d fleet-server

Stdlib-only (no pip deps).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
HARNESS_DIR = REPO_ROOT / ".harness"
ENV_FILE = HARNESS_DIR / "elastic.env"
CA_FILE = HARNESS_DIR / "elastic-ca.crt"
COMPOSE_FILE = REPO_ROOT / "compose.elastic.yaml"

ES_URL = os.environ.get("ELASTIC_URL", "https://localhost:9200")
KIBANA_URL = os.environ.get("KIBANA_URL", "https://localhost:5601")
FLEET_URL = os.environ.get("FLEET_URL", "https://fleet-server:8220")
ELASTIC_USER = os.environ.get("ELASTIC_USERNAME", "elastic")
ELASTIC_PASS = os.environ.get("ELASTIC_PASSWORD", "changeme")

FLEET_SERVER_POLICY_ID = "fleet-server-policy"
DEFEND_POLICY_ID = "defend-policy"
DEFEND_POLICY_NAME = "Defend (Doomla host)"


# ── HTTP plumbing ────────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _basic(user: str, pw: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def request(method: str, url: str, *, json_body=None, headers=None,
            auth=(ELASTIC_USER, ELASTIC_PASS), expect=(200, 201, 204),
            allow=(), timeout=60):
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)
    if auth:
        h["Authorization"] = _basic(*auth)
    if url.startswith(KIBANA_URL):
        h.setdefault("kbn-xsrf", "edr-elastic-setup")
        h.setdefault("elastic-api-version", "2023-10-31")
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            status = r.status
            payload = r.read()
    except urllib.error.HTTPError as e:
        status = e.code
        payload = e.read()
    if status in expect or status in allow:
        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload.decode(errors="replace")
    sys.stderr.write(
        f"\n[{method} {url}] HTTP {status}\n"
        f"{payload.decode(errors='replace')[:2000]}\n"
    )
    raise SystemExit(f"unexpected HTTP {status} on {method} {url}")


def es(method: str, path: str, **kw):
    return request(method, f"{ES_URL}{path}", **kw)


def kbn(method: str, path: str, **kw):
    return request(method, f"{KIBANA_URL}{path}", **kw)


def wait_for(label: str, fn, timeout_s=600, interval_s=5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            if fn():
                print(f"  ok  {label}")
                return
        except SystemExit:
            raise
        except Exception as exc:
            last = exc
        time.sleep(interval_s)
    raise SystemExit(f"timed out waiting for {label}: {last}")


# ── Steps ────────────────────────────────────────────────────────────────────

def extract_ca() -> None:
    HARNESS_DIR.mkdir(parents=True, exist_ok=True)
    if CA_FILE.exists() and CA_FILE.stat().st_size > 0:
        return
    print("→ extracting CA cert from docker volume")
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "cp",
         "elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt",
         str(CA_FILE)],
        check=True,
    )


def wait_es():
    print("→ waiting for Elasticsearch")
    wait_for(
        "ES yellow/green",
        lambda: es("GET", "/_cluster/health").get("status") in {"yellow", "green"},
    )


def ensure_trial():
    print("→ ensuring trial license")
    lic = (es("GET", "/_license") or {}).get("license", {})
    if lic.get("type") == "trial" and lic.get("status") == "active":
        print(f"  ok  trial active (expires {lic.get('expiry_date')})")
        return
    es("POST", "/_license/start_trial?acknowledge=true")
    print("  ok  trial started")


def wait_kibana():
    print("→ waiting for Kibana")
    def ready():
        s = kbn("GET", "/api/status")
        return (((s or {}).get("status") or {}).get("overall") or {}).get("level") == "available"
    wait_for("Kibana available", ready)


def fleet_setup():
    print("→ POST /api/fleet/setup")
    kbn("POST", "/api/fleet/setup")
    kbn("POST", "/api/fleet/agents/setup")


def configure_default_output():
    # The auto-created `fleet-default-output` ships with hosts=
    # ["http://localhost:9200"] (plaintext) and no CA trust config. Both
    # Defend's endpoint binary and the beats/otel monitoring components
    # fail TLS handshake against our self-signed ES until we (a) point at
    # https, (b) pin the CA fingerprint for Beats/otel, and (c) inline the
    # CA PEM in config_yaml — the endpoint binary doesn't honor the
    # fingerprint alone.
    print("→ configuring fleet-default-output for https + CA trust")
    ca_pem = CA_FILE.read_text()
    der = ssl.PEM_cert_to_DER_cert(ca_pem)
    fp = hashlib.sha256(der).hexdigest()
    indented = "\n".join("    " + l for l in ca_pem.rstrip().splitlines())
    config_yaml = "ssl:\n  certificate_authorities:\n  - |\n" + indented + "\n"
    kbn(
        "PUT",
        "/api/fleet/outputs/fleet-default-output",
        json_body={
            "name": "default",
            "type": "elasticsearch",
            "hosts": ["https://localhost:9200"],
            "is_default": True,
            "is_default_monitoring": True,
            "ca_trusted_fingerprint": fp,
            "config_yaml": config_yaml,
        },
    )
    print(f"  ok  hosts=https://localhost:9200  ca_fp={fp[:16]}…")


def get_policy(policy_id):
    r = request(
        "GET", f"{KIBANA_URL}/api/fleet/agent_policies/{policy_id}",
        expect=(200,), allow=(404,),
    )
    return (r or {}).get("item") if isinstance(r, dict) else None


def ensure_fleet_server_policy():
    print("→ ensuring Fleet Server policy")
    if get_policy(FLEET_SERVER_POLICY_ID):
        print("  ok  exists")
        return
    kbn("POST", "/api/fleet/agent_policies?sys_monitoring=true", json_body={
        "id": FLEET_SERVER_POLICY_ID,
        "name": "Fleet Server policy",
        "namespace": "default",
        "has_fleet_server": True,
        "monitoring_enabled": ["logs", "metrics"],
    })
    print("  ok  created (Fleet Server integration auto-attached)")


def mint_fleet_service_token():
    print("→ minting Fleet Server service token")
    r = kbn("POST", "/api/fleet/service_tokens", json_body={})
    return r["value"]


def ensure_defend_policy():
    print("→ ensuring Defend agent policy")
    if get_policy(DEFEND_POLICY_ID):
        print("  ok  exists")
        return
    kbn("POST", "/api/fleet/agent_policies?sys_monitoring=true", json_body={
        "id": DEFEND_POLICY_ID,
        "name": DEFEND_POLICY_NAME,
        "namespace": "default",
        "monitoring_enabled": ["logs", "metrics"],
    })
    print("  ok  created (empty — add Endpoint integration via Kibana UI)")


def has_endpoint_integration() -> bool:
    pol = get_policy(DEFEND_POLICY_ID) or {}
    for pp in pol.get("package_policies") or []:
        pkg = ((pp.get("package") or {}).get("name") or "").lower()
        if pkg == "endpoint":
            return True
    return False


def get_enrollment_token():
    print("→ fetching Defend enrollment token")
    r = kbn("GET", "/api/fleet/enrollment_api_keys?perPage=100") or {}
    for k in (r.get("items") or r.get("list") or []):
        if k.get("policy_id") == DEFEND_POLICY_ID and k.get("active"):
            return k["api_key"]
    return None


def install_prebuilt_rules():
    print("→ installing Prebuilt Detection Rules library (may take 2-5 min)")
    r = kbn("PUT", "/api/detection_engine/rules/prepackaged",
            expect=(200, 201), timeout=900)
    if isinstance(r, dict):
        print(f"  ok  rules_installed={r.get('rules_installed')} "
              f"rules_updated={r.get('rules_updated')}")
    else:
        print("  ok  install/update complete")


def enable_prebuilt_rules():
    print("→ enabling all prebuilt detection rules (batches of 100)")
    # Find all immutable disabled rules first (page size 100 to match bulk_action limit).
    all_ids = []
    page = 1
    while True:
        r = kbn("GET",
                "/api/detection_engine/rules/_find"
                f"?per_page=100&page={page}"
                "&filter=alert.attributes.params.immutable:true"
                "%20and%20alert.attributes.enabled:false",
                timeout=120) or {}
        items = r.get("data") or []
        all_ids.extend(it["id"] for it in items)
        if len(items) < 100:
            break
        page += 1
    print(f"  found {len(all_ids)} disabled prebuilt rules")
    for i in range(0, len(all_ids), 100):
        batch = all_ids[i:i + 100]
        kbn("POST", "/api/detection_engine/rules/_bulk_action?dry_run=false",
            json_body={"action": "enable", "ids": batch},
            timeout=300)
        print(f"  ok  enabled {i + len(batch)}/{len(all_ids)}")
    print(f"  ok  total newly-enabled: {len(all_ids)}")


def mint_reader_api_key():
    print("→ minting alert-reader API key (Phase 2)")
    name = "edr-elastic-alert-reader"
    existing = (es("GET", f"/_security/api_key?name={name}") or {}).get("api_keys", [])
    stale = [k["id"] for k in existing if not k.get("invalidated")]
    if stale:
        es("DELETE", "/_security/api_key", json_body={"ids": stale})
    r = es("POST", "/_security/api_key", json_body={
        "name": name,
        "role_descriptors": {
            "alerts-reader": {
                "cluster": ["monitor"],
                "indices": [{
                    "names": ["logs-endpoint.alerts-*", ".alerts-security.alerts-*"],
                    "privileges": ["read", "view_index_metadata"],
                }],
            },
        },
    })
    return r["encoded"]


def discover_monitored_agent():
    print("→ checking for enrolled Defend agent")
    r = kbn("GET",
            f"/api/fleet/agents?kuery=policy_id:%22{DEFEND_POLICY_ID}%22"
            "&showInactive=false&perPage=20") or {}
    agents = r.get("items") or r.get("list") or []
    online = [a for a in agents if a.get("status") in {"online", "healthy"}]
    if not online:
        return None
    a = online[0]
    return a.get("id") or (a.get("agent") or {}).get("id")


def write_env(values):
    HARNESS_DIR.mkdir(parents=True, exist_ok=True)
    lines = [f"{k}={v}" for k, v in values.items() if v is not None]
    ENV_FILE.write_text("\n".join(lines) + "\n")
    os.chmod(ENV_FILE, 0o600)
    print(f"→ wrote {ENV_FILE}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    extract_ca()
    wait_es()
    ensure_trial()
    wait_kibana()
    fleet_setup()
    configure_default_output()

    ensure_fleet_server_policy()
    fleet_token = mint_fleet_service_token()

    ensure_defend_policy()
    endpoint_attached = has_endpoint_integration()
    enrollment_token = get_enrollment_token() if endpoint_attached else None

    install_prebuilt_rules()
    enable_prebuilt_rules()

    api_key = mint_reader_api_key()
    agent_id = discover_monitored_agent() if endpoint_attached else None

    write_env({
        "ELASTIC_URL": ES_URL,
        "KIBANA_URL": KIBANA_URL,
        "FLEET_URL": FLEET_URL,
        "ELASTIC_CA_CERT_PATH": str(CA_FILE),
        "ELASTIC_USERNAME": ELASTIC_USER,
        "ELASTIC_PASSWORD": ELASTIC_PASS,
        "ES_API_KEY": api_key,
        "FLEET_SERVER_SERVICE_TOKEN": fleet_token,
        "FLEET_SERVER_POLICY_ID": FLEET_SERVER_POLICY_ID,
        "DEFEND_POLICY_ID": DEFEND_POLICY_ID,
        # Named DEFEND_ENROLLMENT_TOKEN (not FLEET_ENROLLMENT_TOKEN) because
        # the elastic-agent docker image auto-detects FLEET_ENROLLMENT_TOKEN
        # in its env_file and enrolls the embedded agent with it — which
        # would put the fleet-server container on the wrong policy.
        "DEFEND_ENROLLMENT_TOKEN": enrollment_token,
        "MONITORED_AGENT_ID": agent_id,
    })

    print("\n" + "=" * 64)
    print("Phase 1 setup script done.")
    print("=" * 64)
    if not endpoint_attached:
        print(
            "\nNEXT (manual, Kibana UI):\n"
            f"  1. Open {KIBANA_URL} → Fleet → Agent policies → 'Defend (Doomla host)'\n"
            "  2. Add integration → Elastic Defend → preset 'Complete EDR'\n"
            "  3. Confirm prevent mode on malware / ransomware / memory_threat / malicious_behavior\n"
            "  4. Save\n"
            "Then re-run setup_elastic.py to fetch the enrollment token.\n"
        )
        sys.exit(2)
    if agent_id is None:
        print(
            "\nNEXT (Doomla docker host):\n"
            f"  sudo elastic-agent install \\\n"
            f"    --url={FLEET_URL.replace('fleet-server', '<eval-host-ip>')} \\\n"
            f"    --enrollment-token={enrollment_token} \\\n"
            f"    --certificate-authorities={CA_FILE} \\\n"
            f"    --insecure\n"
            "Then re-run setup_elastic.py to populate MONITORED_AGENT_ID.\n"
        )
        sys.exit(3)
    print(f"\nMonitored agent: {agent_id}\nReady for verify_phase1.py.\n")


if __name__ == "__main__":
    main()
