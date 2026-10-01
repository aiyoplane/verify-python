# aiyoplane-verify

**Offline Ed25519 verifier for Aiyo execution receipts.**

Aiyo issues cryptographically-signed **execution receipts** at the moment it authorizes a consequential action. Every receipt is verifiable offline against Aiyo's published JWKS — no round-trip to Aiyo required at verification time, no Aiyo-side infrastructure needed. This package is the Python verifier.

Aiyoplane, Inc. · Apache 2.0 licensed · [aiyoplane.com](https://aiyoplane.com)

The npm port (same spec, same JWKS, same semantics) is published as [`@aiyoplane/verify`](https://www.npmjs.com/package/@aiyoplane/verify).

---

## Install

```sh
pip install aiyoplane-verify
```

Requires Python 3.9+ and the `cryptography` package (installed automatically as a dependency).

---

## Command-line usage

The install registers a console script `aiyo-verify` in your Python environment:

```sh
# Verify a receipt from a file
aiyo-verify path/to/receipt.txt

# Verify a receipt passed inline
aiyo-verify --receipt "v2.eyJpaWQiOiJpbnRlbnRfMTIz...Q.MEQCIH...IDA"

# Read from stdin
cat receipt.txt | aiyo-verify -

# Emit JSON output for CI/CD or machine consumption
aiyo-verify --json path/to/receipt.txt

# Override the JWKS URL (e.g., for a self-hosted Aiyo instance)
aiyo-verify --jwks-url https://api.example.com/.well-known/aiyo-jwks.json path/to/receipt.txt
```

**Exit codes:**
- `0` — receipt verified successfully
- `1` — receipt invalid (bad signature, expired, malformed, unknown key)
- `2` — usage error (missing input, unrecognized flag, etc.)

---

## Programmatic usage

```python
from aiyoplane_verify import verify, ReceiptExpiredError, ReceiptSignatureError

receipt = "v2.eyJpaWQiOiJpbnRlbnRfMTIz...Q.MEQCIH...IDA"

try:
    result = verify(receipt)
    claims = result["claims"]
    print(f"Authorized action {claims['iid']} for merchant {claims['mid']}")
    print(f"Receipt valid until {claims['exp']}")
except ReceiptExpiredError:
    # Receipt was validly signed but has expired.
    ...
except ReceiptSignatureError:
    # Signature did not verify — possible tampering or key mismatch.
    ...
```

### Options

```python
from datetime import datetime, timezone
import os
from aiyoplane_verify import verify

result = verify(
    receipt,
    # Override the JWKS URL (default: https://api.aiyoplane.com/.well-known/aiyo-jwks.json)
    jwks_url="https://api.example.com/.well-known/aiyo-jwks.json",

    # Required for v1 HMAC receipts (local development only).
    hmac_secret=os.environ.get("AIYO_HMAC_SECRET"),

    # Override "now" for expiration checks (useful in tests). Accepts a
    # datetime or a float of epoch seconds.
    now=datetime(2026, 9, 28, 14, 24, tzinfo=timezone.utc),

    # Clock-skew tolerance in seconds (default: 30).
    clock_skew_seconds=60,

    # Timeout for JWKS fetch, if needed. Default 10 seconds.
    timeout_seconds=5.0,
)
```

### Typed errors

Every verification failure raises one of these typed exceptions. Handle specific failure modes distinctly:

```python
from aiyoplane_verify import (
    verify,
    ReceiptFormatError,
    ReceiptSignatureError,
    ReceiptExpiredError,
    JwksFetchError,
    UnknownKeyError,
    UnsupportedVersionError,
)

try:
    verify(receipt)
except ReceiptExpiredError:
    # Receipt was validly signed but has expired.
    ...
except ReceiptSignatureError:
    # Signature did not verify — possible tampering or key mismatch.
    ...
except JwksFetchError:
    # Could not reach the JWKS endpoint — treat as transient and retry.
    ...
except (ReceiptFormatError, UnknownKeyError, UnsupportedVersionError):
    # Malformed receipt, unknown kid, or unsupported version.
    ...
```

---

## Receipt format

Aiyo receipts are strings of the form:

```
v2.<base64url(payload_json)>.<base64url(ed25519_signature)>
```

The payload is a JSON object with these required claims:

| Claim | Type | Meaning |
|---|---|---|
| `iid` | string | Intent ID — the specific action this receipt authorized |
| `mid` | string | Merchant ID — whose policy this decision was under |
| `exp` | number | Expiration timestamp (unix seconds) |
| `iat` | number | Issued-at timestamp (unix seconds) |
| `cid` | string | Context ID — correlation across a broader flow (optional) |
| `kid` | string | Key ID — which JWKS key was used to sign (optional) |

The signature is Ed25519 over the base64url-encoded payload segment (JWS-style compact signing).

The v1 format (`v1.…`) uses HMAC-SHA256 with a shared secret and is intended for local development / in-process use only. Production receipts should always be v2.

---

## JWKS

The default JWKS URL is:

```
https://api.aiyoplane.com/.well-known/aiyo-jwks.json
```

Keys are cached in-memory (respecting `Cache-Control: max-age` where present, defaulting to 10 minutes). If a receipt references a `kid` not in the cache, the JWKS is automatically refreshed once — handling key rotation gracefully.

To force a fresh JWKS fetch in a long-running process:

```python
from aiyoplane_verify import clear_jwks_cache, fetch_jwks

clear_jwks_cache()
fetch_jwks()  # Refetches from the default URL
```

---

## Why offline verification matters

Third parties — auditors, downstream systems, merchants' own compliance tooling — can verify Aiyo receipts without depending on Aiyo being available at verification time. The receipt is a **portable, independently-verifiable artifact**. That's the property that makes Aiyo's authorization decision durable across systems, and it's the property this package makes trivial to use.

For the broader architectural context, see the [DMARC precedent post](https://aiyoplane.com/blog/aiyo-dmarc-precedent) and the [MCP-authz reference implementation](https://github.com/aiyoplane/mcp-authz).

---

## About Aiyo

Aiyo is the settlement-verified Economic Execution Authorization plane for autonomous systems. Its Runtime Decision Point verifies that settlement actually occurred on a real rail, evaluates merchant policy, and issues a portable authorization artifact that unlocks the action a payment — or any qualifying condition — was supposed to enable. **Verify First. Execute Second.**

[aiyoplane.com](https://aiyoplane.com)

---

## License

Apache License 2.0 © 2026 Aiyoplane, Inc. — see `LICENSE` and `NOTICE`.
