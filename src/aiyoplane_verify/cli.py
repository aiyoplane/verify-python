#!/usr/bin/env python3
"""CLI entry point for aiyoplane-verify.

Usage:
  aiyo-verify <receipt-file>
  aiyo-verify --receipt "<receipt-string>"
  cat receipt.txt | aiyo-verify -

Options:
  --jwks-url <url>        Override the default JWKS URL
  --hmac-secret <secret>  Required for v1 HMAC receipts (local dev only)
  --json                  Emit machine-readable JSON output (default: human-readable)
  --help                  Show help
  --version               Show version

Exit codes:
  0 - receipt verified
  1 - receipt invalid (bad signature, expired, malformed, unknown key)
  2 - usage error
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aiyoplane_verify import __version__
from aiyoplane_verify.errors import AiyoVerifyError
from aiyoplane_verify.jwks import DEFAULT_JWKS_URL
from aiyoplane_verify.verify import verify_receipt

HELP = """aiyoplane-verify - Offline Ed25519 verifier for Aiyo execution receipts

Usage:
  aiyo-verify <receipt-file>
  aiyo-verify --receipt "<receipt-string>"
  cat receipt.txt | aiyo-verify -

Options:
  --jwks-url <url>        Override the default JWKS URL
                          Default: https://api.aiyoplane.com/.well-known/aiyo-jwks.json
  --hmac-secret <secret>  Required for v1 HMAC receipts (local development only)
  --json                  Emit machine-readable JSON output
  --help                  Show this help
  --version               Show version

Exit codes:
  0  Receipt verified successfully
  1  Receipt invalid (bad signature, expired, malformed, unknown key)
  2  Usage error
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aiyo-verify",
        description="Offline Ed25519 verifier for Aiyo execution receipts",
        add_help=False,
    )
    parser.add_argument("receipt_file", nargs="?", help='Path to a receipt file, or "-" for stdin')
    parser.add_argument("--receipt", dest="receipt_inline", help="Receipt string passed inline")
    parser.add_argument(
        "--jwks-url",
        dest="jwks_url",
        default=DEFAULT_JWKS_URL,
        help="Override the default JWKS URL",
    )
    parser.add_argument(
        "--hmac-secret",
        dest="hmac_secret",
        help="Required for v1 HMAC receipts (local development only)",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit JSON output")
    parser.add_argument("--help", "-h", dest="help", action="store_true", help="Show help")
    parser.add_argument(
        "--version",
        "-v",
        dest="version_flag",
        action="store_true",
        help="Show version",
    )
    return parser


def _read_receipt(args: argparse.Namespace) -> str:
    if args.receipt_inline:
        return args.receipt_inline.strip()
    first = args.receipt_file
    if first == "-":
        return sys.stdin.read().strip()
    if first:
        return Path(first).read_text(encoding="utf-8").strip()
    raise ValueError(
        'No receipt provided. Pass a filename, use --receipt "<string>", or pipe via stdin ("-").'
    )


def _format_timestamp(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.help:
        sys.stdout.write(HELP)
        return 0

    if args.version_flag:
        sys.stdout.write(f"{__version__}\n")
        return 0

    try:
        receipt = _read_receipt(args)
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"Error: {exc}\n\n{HELP}")
        return 2

    try:
        result = verify_receipt(
            receipt,
            jwks_url=args.jwks_url,
            hmac_secret=args.hmac_secret,
        )
        if args.json_output:
            sys.stdout.write(
                json.dumps(
                    {
                        "valid": True,
                        "version": result["version"],
                        "claims": result["claims"],
                    },
                    indent=2,
                )
                + "\n"
            )
        else:
            claims = result["claims"]
            sys.stdout.write(f"✓ Valid receipt ({result['version']})\n")
            sys.stdout.write(f"  intent_id:   {claims['iid']}\n")
            if claims.get("cid"):
                sys.stdout.write(f"  context_id:  {claims['cid']}\n")
            sys.stdout.write(f"  merchant_id: {claims['mid']}\n")
            sys.stdout.write(f"  issued_at:   {_format_timestamp(float(claims['iat']))}\n")
            sys.stdout.write(f"  expires_at:  {_format_timestamp(float(claims['exp']))}\n")
        return 0
    except AiyoVerifyError as exc:
        if args.json_output:
            body = {"valid": False, "error": str(exc)}
            if exc.code:
                body["code"] = exc.code
            sys.stderr.write(json.dumps(body, indent=2) + "\n")
        else:
            sys.stderr.write(f"✗ Verification failed: {exc}\n")
            if exc.code:
                sys.stderr.write(f"  ({exc.code})\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
