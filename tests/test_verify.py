"""Basic tests for aiyoplane-verify.

Run with: pytest tests/
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from aiyoplane_verify import (
    ReceiptExpiredError,
    ReceiptFormatError,
    ReceiptSignatureError,
    UnsupportedVersionError,
    verify,
)

HMAC_SECRET = "test-secret-do-not-use-in-production"


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_v1_receipt(claims: dict, secret: str = HMAC_SECRET) -> str:
    payload_json = json.dumps(claims, separators=(",", ":"), sort_keys=True)
    payload_b64 = _base64url_encode(payload_json.encode("utf-8"))
    signed_bytes = payload_b64.encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signed_bytes, hashlib.sha256).digest()
    sig_b64 = _base64url_encode(signature)
    return f"v1.{payload_b64}.{sig_b64}"


NOW = int(time.time())
VALID_CLAIMS = {
    "iid": "intent_test_001",
    "mid": "mrch_test",
    "iat": NOW,
    "exp": NOW + 300,
}


def test_verify_returns_valid_for_well_formed_v1_receipt():
    receipt = _make_v1_receipt(VALID_CLAIMS)
    result = verify(receipt, hmac_secret=HMAC_SECRET)
    assert result["valid"] is True
    assert result["version"] == "v1"
    assert result["claims"]["iid"] == "intent_test_001"


def test_verify_raises_format_error_for_non_string_receipt():
    with pytest.raises(ReceiptFormatError):
        verify(None, hmac_secret=HMAC_SECRET)  # type: ignore[arg-type]


def test_verify_raises_format_error_for_receipt_missing_parts():
    with pytest.raises(ReceiptFormatError):
        verify("v1.onlyonepart", hmac_secret=HMAC_SECRET)


def test_verify_raises_unsupported_version_for_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        verify("v9.abc.def", hmac_secret=HMAC_SECRET)


def test_verify_raises_signature_error_when_v1_signature_tampered():
    receipt = _make_v1_receipt(VALID_CLAIMS)
    parts = receipt.split(".")
    tampered = f"{parts[0]}.{parts[1]}.{_base64url_encode(b'0' * 32)}"
    with pytest.raises(ReceiptSignatureError):
        verify(tampered, hmac_secret=HMAC_SECRET)


def test_verify_raises_signature_error_with_wrong_secret():
    receipt = _make_v1_receipt(VALID_CLAIMS)
    with pytest.raises(ReceiptSignatureError):
        verify(receipt, hmac_secret="wrong-secret")


def test_verify_raises_expired_error_when_receipt_has_expired():
    expired = dict(VALID_CLAIMS)
    expired["iat"] = NOW - 600
    expired["exp"] = NOW - 300
    receipt = _make_v1_receipt(expired)
    with pytest.raises(ReceiptExpiredError):
        verify(receipt, hmac_secret=HMAC_SECRET)


def test_verify_honors_clock_skew_tolerance():
    expired = dict(VALID_CLAIMS)
    expired["iat"] = NOW - 60
    expired["exp"] = NOW - 10
    receipt = _make_v1_receipt(expired)
    # With generous skew tolerance, should still pass.
    result = verify(receipt, hmac_secret=HMAC_SECRET, clock_skew_seconds=60)
    assert result["valid"] is True


def test_verify_raises_signature_error_when_v1_has_no_hmac_secret():
    receipt = _make_v1_receipt(VALID_CLAIMS)
    with pytest.raises(ReceiptSignatureError):
        verify(receipt)


def test_verify_raises_format_error_when_payload_missing_required_claims():
    incomplete = {"iid": "intent_test", "mid": "mrch_test"}
    receipt = _make_v1_receipt(incomplete)
    with pytest.raises(ReceiptFormatError):
        verify(receipt, hmac_secret=HMAC_SECRET)
