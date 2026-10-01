"""aiyoplane-verify.

Offline Ed25519 verifier for Aiyo execution receipts.

Aiyoplane, Inc. - Apache 2.0 licensed.
https://aiyoplane.com
"""

from aiyoplane_verify.errors import (
    AiyoVerifyError,
    JwksFetchError,
    ReceiptExpiredError,
    ReceiptFormatError,
    ReceiptSignatureError,
    UnknownKeyError,
    UnsupportedVersionError,
)
from aiyoplane_verify.jwks import clear_jwks_cache, fetch_jwks
from aiyoplane_verify.verify import verify, verify_receipt

__version__ = "1.0.2"

__all__ = [
    "verify",
    "verify_receipt",
    "fetch_jwks",
    "clear_jwks_cache",
    "AiyoVerifyError",
    "ReceiptFormatError",
    "ReceiptSignatureError",
    "ReceiptExpiredError",
    "JwksFetchError",
    "UnknownKeyError",
    "UnsupportedVersionError",
    "__version__",
]
