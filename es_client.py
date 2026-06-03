"""Thin wrapper that builds an Elasticsearch client from .harness/elastic.env.

The Phase 1 setup script writes a read-only API key into
`.harness/elastic.env`. This module loads that env file, builds an
authenticated client, and (by default) verifies TLS against the
Phase 1 CA at `.harness/elastic-ca.crt`.

For local dev where the CA chain is awkward, set `ELASTIC_INSECURE=1` to
disable verification. The default is to verify.

The API key value is never echoed in exception messages or logs. We
deliberately let `KeyError` raise on missing keys rather than f-string
the value into a custom message.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from elasticsearch import Elasticsearch

DEFAULT_ENV_PATH = Path(__file__).resolve().parent / ".harness" / "elastic.env"


def load_env(path: Path | str | None = None) -> dict[str, str]:
    """Read `.harness/elastic.env` into a dict of strings.

    Empty values are dropped so downstream code can rely on
    `env.get(key)` returning a truthy value for keys that are actually
    set.
    """
    env_path = Path(path) if path else DEFAULT_ENV_PATH
    if not env_path.exists():
        raise FileNotFoundError(
            f"{env_path} missing; run setup_elastic.py first"
        )
    raw = dotenv_values(env_path)
    return {k: v for k, v in raw.items() if v}


def make_client(
    env: dict[str, str] | None = None,
    *,
    env_path: Path | str | None = None,
) -> Elasticsearch:
    """Construct an Elasticsearch client with API-key auth.

    TLS verification is on by default. The CA is taken from
    `ELASTIC_CA_CERT_PATH` in the env file. Set the environment
    variable `ELASTIC_INSECURE=1` to skip verification (local dev only).
    """
    if env is None:
        env = load_env(env_path)

    url = env["ELASTIC_URL"]
    api_key = env["ES_API_KEY"]
    insecure = os.environ.get("ELASTIC_INSECURE") == "1"

    kwargs: dict[str, Any] = {
        "hosts": [url],
        "api_key": api_key,
        "request_timeout": 15,
    }
    if insecure:
        kwargs["verify_certs"] = False
        kwargs["ssl_show_warn"] = False
    else:
        ca_path = env.get("ELASTIC_CA_CERT_PATH")
        if ca_path and Path(ca_path).exists():
            kwargs["ca_certs"] = ca_path
        # Phase 1 issues certs for `localhost` / service DNS names; when
        # the client connects via 127.0.0.1 the hostname check would fail
        # against `localhost`. Trust the CA pin instead.
        kwargs.setdefault("ssl_assert_hostname", False)

    return Elasticsearch(**kwargs)
