"""JWKS fetch + in-memory cache.

Aiyo publishes its Ed25519 public keys at a standard JWKS URL. This module:
  1. Fetches the JWKS on first use.
  2. Caches keys in-memory (respecting Cache-Control headers where present).
  3. Refreshes on demand if verification fails against the current cache
     (handling key rotation gracefully).

Uses stdlib urllib.request to maintain zero runtime HTTP dependencies.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from typing import Dict, Optional
from urllib.error import HTTPError, URLError

from aiyoplane_verify.errors import JwksFetchError, UnknownKeyError

DEFAULT_JWKS_URL = "https://api.aiyoplane.com/.well-known/aiyo-jwks.json"

# In-memory JWKS cache keyed by URL.
# Structure: {url: {"keys": {kid: jwk}, "fetched_at": epoch_seconds, "ttl": seconds}}
_CACHE: Dict[str, Dict[str, object]] = {}

# Default TTL when the server doesn't set a Cache-Control max-age.
_DEFAULT_TTL_SECONDS = 10 * 60  # 10 minutes


def fetch_jwks(
    url: str = DEFAULT_JWKS_URL,
    *,
    force_refresh: bool = False,
    timeout_seconds: float = 10.0,
) -> Dict[str, Dict]:
    """Fetch the JWKS from the given URL (or the Aiyo default) and cache it.

    If the URL is already cached and not expired, returns the cached copy.
    Pass force_refresh=True to bypass the cache.

    Returns:
        A dict mapping kid -> jwk (the JWK is itself a dict).

    Raises:
        JwksFetchError: on any network or parse failure.
    """
    now = time.time()
    cached = _CACHE.get(url)
    if not force_refresh and cached is not None:
        fetched_at = float(cached["fetched_at"])  # type: ignore[arg-type]
        ttl = float(cached["ttl"])  # type: ignore[arg-type]
        if (now - fetched_at) < ttl:
            return cached["keys"]  # type: ignore[return-value]

    req = urllib.request.Request(
        url,
        headers={"Accept": "application/jwk-set+json, application/json"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            raw_body = response.read()
            cache_control = response.headers.get("Cache-Control", "") or ""
    except HTTPError as exc:
        raise JwksFetchError(
            f"JWKS fetch returned HTTP {exc.code} from {url}",
            cause=exc,
        ) from exc
    except URLError as exc:
        raise JwksFetchError(
            f"Failed to fetch JWKS from {url}: {exc.reason}",
            cause=exc,
        ) from exc
    except Exception as exc:  # noqa: BLE001 - preserve original cause via chain
        raise JwksFetchError(
            f"Failed to fetch JWKS from {url}: {exc}",
            cause=exc,
        ) from exc

    try:
        body = json.loads(raw_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwksFetchError(
            f"JWKS response was not valid JSON: {exc}",
            cause=exc,
        ) from exc

    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        raise JwksFetchError('JWKS response missing required "keys" array')

    # Build a {kid: jwk} map for O(1) lookup by key ID.
    key_map: Dict[str, Dict] = {}
    for jwk in body["keys"]:
        if isinstance(jwk, dict) and isinstance(jwk.get("kid"), str):
            key_map[jwk["kid"]] = jwk

    # Respect the server's Cache-Control max-age if present.
    max_age_match = re.search(r"max-age=(\d+)", cache_control, flags=re.IGNORECASE)
    ttl = float(max_age_match.group(1)) if max_age_match else float(_DEFAULT_TTL_SECONDS)

    _CACHE[url] = {"keys": key_map, "fetched_at": now, "ttl": ttl}
    return key_map


def resolve_key(
    kid: str,
    url: str = DEFAULT_JWKS_URL,
    *,
    timeout_seconds: float = 10.0,
) -> Dict:
    """Resolve a specific key by kid.

    Fetches the JWKS if not cached, and refreshes the cache once if the
    requested kid is not present (handles key rotation).

    Raises:
        UnknownKeyError: if the kid cannot be resolved even after refresh.
        JwksFetchError: on any network or parse failure.
    """
    keys = fetch_jwks(url, timeout_seconds=timeout_seconds)
    if kid not in keys:
        # Key rotation may have added a new kid we don't have cached. Refresh once.
        keys = fetch_jwks(url, force_refresh=True, timeout_seconds=timeout_seconds)
    jwk = keys.get(kid)
    if jwk is None:
        raise UnknownKeyError(f'No JWK found for kid="{kid}" in {url}')
    return jwk


def clear_jwks_cache(url: Optional[str] = None) -> None:
    """Clear the in-memory JWKS cache.

    Pass a URL to clear only that URL's cached JWKS; omit to clear all.
    """
    if url is not None:
        _CACHE.pop(url, None)
    else:
        _CACHE.clear()
