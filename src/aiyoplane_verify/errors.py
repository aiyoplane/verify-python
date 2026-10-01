"""Typed errors for aiyoplane-verify.

Every verification failure raises one of these -- never a generic Exception.
This lets integrators handle specific failure modes distinctly.
"""

from __future__ import annotations

from typing import Optional


class AiyoVerifyError(Exception):
    """Base class for all aiyoplane-verify errors."""

    code: Optional[str] = None

    def __init__(self, message: str, *, code: Optional[str] = None, cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code
        self.__cause__ = cause


class ReceiptFormatError(AiyoVerifyError):
    """The receipt string is malformed, empty, or structurally invalid."""

    code = "RECEIPT_FORMAT"


class ReceiptSignatureError(AiyoVerifyError):
    """The receipt's cryptographic signature failed verification."""

    code = "SIGNATURE_INVALID"


class ReceiptExpiredError(AiyoVerifyError):
    """The receipt is well-formed and validly signed but has expired."""

    code = "RECEIPT_EXPIRED"


class JwksFetchError(AiyoVerifyError):
    """Could not fetch the JWKS from the configured endpoint."""

    code = "JWKS_FETCH"


class UnknownKeyError(AiyoVerifyError):
    """The receipt references a kid not present in the fetched JWKS."""

    code = "UNKNOWN_KEY"


class UnsupportedVersionError(AiyoVerifyError):
    """The receipt's version prefix is not one this verifier supports."""

    code = "UNSUPPORTED_VERSION"
