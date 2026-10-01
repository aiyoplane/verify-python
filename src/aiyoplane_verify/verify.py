"""aiyoplane-verify - receipt verification core.

Verifies Aiyo execution receipts in the v2 format:
  v2.<base64url(payload_json)>.<base64url(ed25519_signature)>

The payload is a JSON object with the claims:
  { iid, cid, mid, exp, iat }
    iid - intent ID (the specific action that was authorized)
    cid - context ID (correlation across a broader flow, if applicable)
    mid - merchant ID (which merchant's policy this decision was under)
    exp - expiration timestamp (unix seconds); receipt is invalid after this
    iat - issued-at timestamp (unix seconds)

The signature is Ed25519, produced by Aiyo's active signing key. The public
key is fetched from Aiyo's published JWKS (see jwks.py). Verification is
entirely offline once the JWKS is cached -- no round-trip to Aiyo at verify
time.

v1 receipts (HMAC-SHA256) are supported for local development and testing
only, and require an explicit shared secret.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aiyoplane_verify.errors import (
    ReceiptExpiredError,
    ReceiptFormatError,
    ReceiptSignatureError,
    UnsupportedVersionError,
)
from aiyoplane_verify.jwks import DEFAULT_JWKS_URL, fetch_jwks, resolve_key

_V2 = "v2"
_V1 = "v1"


def verify(
    receipt: str,
    *,
    jwks_url: str = DEFAULT_JWKS_URL,
    hmac_secret: Optional[str] = None,
    now: Optional[Union[datetime, float]] = None,
    clock_skew_seconds: int = 30,
    timeout_seconds: float = 10.0,
) -> Dict[str, Any]:
    """Verify an Aiyo execution receipt.

    Args:
        receipt: The receipt string, prefixed with its version (e.g. "v2.…").
        jwks_url: Override the default JWKS URL.
        hmac_secret: Required for v1 HMAC receipts (local dev only).
        now: Override the current time for expiration checks (testing).
        clock_skew_seconds: Tolerance for clock skew. Default 30 seconds.
        timeout_seconds: Timeout for JWKS fetch, if needed. Default 10 seconds.

    Returns:
        A dict: {"valid": True, "version": "v2"|"v1", "claims": {...}}

    Raises:
        ReceiptFormatError: receipt string is malformed.
        ReceiptSignatureError: signature verification failed.
        ReceiptExpiredError: receipt is past its expiration.
        UnsupportedVersionError: version prefix is unknown.
        JwksFetchError: could not fetch JWKS (v2 only).
        UnknownKeyError: referenced kid is not in the JWKS (v2 only).
    """
    return verify_receipt(
        receipt,
        jwks_url=jwks_url,
        hmac_secret=hmac_secret,
        now=now,
        clock_skew_seconds=clock_skew_seconds,
        timeout_seconds=timeout_seconds,
    )


def verify_receipt(
    receipt: str,
    *,
    jwks_url: str = DEFAULT_JWKS_URL,
    hmac_secret: Optional[str] = None,
    now: Optional[Union[datetime, float]] = None,
    clock_skew_seconds: int = 30,
    timeout_seconds: float = 10.0,
) -> Dict[str, Any]:
    """Alias for verify() with explicit naming. See verify() for docs."""
    if not isinstance(receipt, str) or not receipt:
        raise ReceiptFormatError("Receipt must be a non-empty string")

    parts = receipt.split(".")
    if len(parts) != 3:
        raise ReceiptFormatError(f"Receipt must have 3 dot-separated parts, got {len(parts)}")

    version, payload_b64, signature_b64 = parts

    if version == _V2:
        return _verify_v2(
            payload_b64,
            signature_b64,
            jwks_url=jwks_url,
            now=now,
            clock_skew_seconds=clock_skew_seconds,
            timeout_seconds=timeout_seconds,
        )
    if version == _V1:
        return _verify_v1(
            payload_b64,
            signature_b64,
            hmac_secret=hmac_secret,
            now=now,
            clock_skew_seconds=clock_skew_seconds,
        )
    raise UnsupportedVersionError(
        f'Unsupported receipt version prefix "{version}". Expected "{_V2}" or "{_V1}".'
    )


# -----------------------------------------------------------------------------
# v2: Ed25519 with JWKS
# -----------------------------------------------------------------------------


def _verify_v2(
    payload_b64: str,
    signature_b64: str,
    *,
    jwks_url: str,
    now: Optional[Union[datetime, float]],
    clock_skew_seconds: int,
    timeout_seconds: float,
) -> Dict[str, Any]:
    payload_bytes = _base64url_decode(payload_b64)
    signature_bytes = _base64url_decode(signature_b64)

    try:
        claims = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReceiptFormatError("v2 payload is not valid JSON", cause=exc) from exc

    _validate_claims(claims)
    _assert_not_expired(claims, now=now, clock_skew_seconds=clock_skew_seconds)

    kid = claims.get("kid") if isinstance(claims.get("kid"), str) else None

    if kid is not None:
        jwk = resolve_key(kid, jwks_url, timeout_seconds=timeout_seconds)
    else:
        jwk = _resolve_default_key(jwks_url, timeout_seconds=timeout_seconds)

    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ReceiptSignatureError(
            f'Expected Ed25519 (OKP/Ed25519) key, got kty="{jwk.get("kty")}" crv="{jwk.get("crv")}"'
        )

    x_b64 = jwk.get("x")
    if not isinstance(x_b64, str):
        raise ReceiptSignatureError('JWK missing required "x" field for Ed25519')

    try:
        public_key_bytes = _base64url_decode(x_b64)
    except ReceiptFormatError as exc:
        raise ReceiptSignatureError(f'Failed to decode JWK "x" field: {exc}') from exc

    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception as exc:  # cryptography raises ValueError for bad key length
        raise ReceiptSignatureError(f"Invalid Ed25519 public key: {exc}") from exc

    # The signed payload is the raw bytes of the base64url-encoded payload as they
    # appear in the receipt string -- matches the npm reference implementation.
    signed_bytes = payload_b64.encode("utf-8")

    try:
        public_key.verify(signature_bytes, signed_bytes)
    except InvalidSignature as exc:
        raise ReceiptSignatureError("v2 Ed25519 signature verification failed") from exc

    return {"valid": True, "version": _V2, "claims": claims}


def _resolve_default_key(jwks_url: str, *, timeout_seconds: float) -> Dict:
    """Resolve the default Ed25519 key when a receipt has no `kid` claim.

    Only works when the JWKS contains exactly one Ed25519 key.
    """
    keys = fetch_jwks(jwks_url, timeout_seconds=timeout_seconds)
    ed25519_keys = [
        k for k in keys.values()
        if isinstance(k, dict) and k.get("kty") == "OKP" and k.get("crv") == "Ed25519"
    ]
    if len(ed25519_keys) == 0:
        raise ReceiptSignatureError("No Ed25519 keys found in JWKS")
    if len(ed25519_keys) > 1:
        raise ReceiptSignatureError(
            "JWKS contains multiple Ed25519 keys and receipt has no `kid` claim. Cannot pick a default."
        )
    return ed25519_keys[0]


# -----------------------------------------------------------------------------
# v1: HMAC-SHA256 (local development only)
# -----------------------------------------------------------------------------


def _verify_v1(
    payload_b64: str,
    signature_b64: str,
    *,
    hmac_secret: Optional[str],
    now: Optional[Union[datetime, float]],
    clock_skew_seconds: int,
) -> Dict[str, Any]:
    payload_bytes = _base64url_decode(payload_b64)
    provided_signature = _base64url_decode(signature_b64)

    try:
        claims = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReceiptFormatError("v1 payload is not valid JSON", cause=exc) from exc

    _validate_claims(claims)
    _assert_not_expired(claims, now=now, clock_skew_seconds=clock_skew_seconds)

    if not isinstance(hmac_secret, str) or not hmac_secret:
        raise ReceiptSignatureError(
            "v1 receipts require hmac_secret. v1 is for local development only; "
            "production receipts should be v2 (Ed25519 + JWKS)."
        )

    signed_bytes = payload_b64.encode("utf-8")
    expected_signature = hmac.new(
        hmac_secret.encode("utf-8"),
        signed_bytes,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(provided_signature, expected_signature):
        raise ReceiptSignatureError("v1 HMAC-SHA256 signature verification failed")

    return {"valid": True, "version": _V1, "claims": claims}


# -----------------------------------------------------------------------------
# Claim + expiration validation
# -----------------------------------------------------------------------------


def _validate_claims(claims: Any) -> None:
    if not isinstance(claims, dict):
        raise ReceiptFormatError("Receipt payload must be a JSON object")
    for field in ("iid", "mid", "exp", "iat"):
        if field not in claims:
            raise ReceiptFormatError(f'Receipt payload missing required claim "{field}"')
    if not isinstance(claims["exp"], (int, float)):
        raise ReceiptFormatError('Claim "exp" must be a number (unix seconds)')
    if not isinstance(claims["iat"], (int, float)):
        raise ReceiptFormatError('Claim "iat" must be a number (unix seconds)')


def _assert_not_expired(
    claims: Dict[str, Any],
    *,
    now: Optional[Union[datetime, float]],
    clock_skew_seconds: int,
) -> None:
    if now is None:
        now_s = time.time()
    elif isinstance(now, datetime):
        now_s = now.replace(tzinfo=now.tzinfo or timezone.utc).timestamp()
    else:
        now_s = float(now)

    skew_s = float(clock_skew_seconds)
    expires_s = float(claims["exp"])

    if now_s > expires_s + skew_s:
        expires_iso = datetime.fromtimestamp(expires_s, tz=timezone.utc).isoformat()
        now_iso = datetime.fromtimestamp(now_s, tz=timezone.utc).isoformat()
        raise ReceiptExpiredError(f"Receipt expired at {expires_iso} (now is {now_iso})")


# -----------------------------------------------------------------------------
# base64url helpers
# -----------------------------------------------------------------------------


def _base64url_decode(data: str) -> bytes:
    """Decode a base64url string, tolerating missing padding."""
    if not isinstance(data, str):
        raise ReceiptFormatError("Expected base64url-encoded string")
    # Add padding if missing.
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ReceiptFormatError(f"Failed to base64url-decode receipt segment: {exc}") from exc
