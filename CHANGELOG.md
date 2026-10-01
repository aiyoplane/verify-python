# Changelog — `aiyoplane-verify` (Python)

All notable changes to this package are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.2] — 2026-10 (packaging polish)

### Changed
- Removed internal setup instructions from the source distribution. The sdist and wheel now ship only end-user artifacts (source, tests, LICENSE, NOTICE, README).
- `pyproject.toml` and `__init__.__version__` bumped to `1.0.2` for the clean release.

### Compatibility
- No API changes. Drop-in replacement for 1.0.1.
- Receipt verification behavior is unchanged. Receipts verifiable by 1.0.1 remain verifiable by 1.0.2.

### Protocol Conformance
- Continues to implement the AEAP receipt verification surface. See [AEAP](https://aiyoplane.com/trust) for the normative specification this package conforms to.

---

## Yanked Versions

The following versions have been yanked on PyPI. They remain installable by exact pin for reproducibility but are skipped by default resolution; `pip install aiyoplane-verify` resolves to the newest unyanked version.

- `1.0.1` — Superseded by 1.0.2 (packaging polish).

---

## Links

- **Package home:** https://pypi.org/project/aiyoplane-verify/
- **Source:** https://github.com/aiyoplane/verify-python
- **AEAP specification:** https://aiyoplane.com/trust
- **Node sibling:** https://www.npmjs.com/package/@aiyoplane/verify
