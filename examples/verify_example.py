"""Example: verify an Aiyo execution receipt programmatically.

Run with: python examples/verify_example.py

Uses a v1 (HMAC) receipt so the example is fully offline. Production receipts
(v2 Ed25519) work the same way but fetch the public key from Aiyo's JWKS URL
automatically.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from aiyoplane_verify import verify

HMAC_SECRET = "local-development-secret"


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_example_receipt() -> str:
    now = int(time.time())
    claims = {
        "iid": "intent_example_001",
        "cid": "ctx_example",
        "mid": "mrch_example",
        "iat": now,
        "exp": now + 300,
    }
    payload_json = json.dumps(claims, separators=(",", ":"), sort_keys=True)
    payload_b64 = _base64url_encode(payload_json.encode("utf-8"))
    signed_bytes = payload_b64.encode("utf-8")
    signature = hmac.new(HMAC_SECRET.encode("utf-8"), signed_bytes, hashlib.sha256).digest()
    return f"v1.{payload_b64}.{_base64url_encode(signature)}"


def main() -> None:
    receipt = _make_example_receipt()
    print("Verifying example receipt:")
    print(f"  {receipt[:40]}...")
    print()

    result = verify(receipt, hmac_secret=HMAC_SECRET)
    claims = result["claims"]
    print("✓ Receipt verified")
    print(f"  version:     {result['version']}")
    print(f"  intent_id:   {claims['iid']}")
    print(f"  context_id:  {claims.get('cid')}")
    print(f"  merchant_id: {claims['mid']}")


if __name__ == "__main__":
    main()
