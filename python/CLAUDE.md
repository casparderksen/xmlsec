# CLAUDE.md — python/

## Goal

Python verifier for detached XML Digital Signatures compatible with `xmlsec1` CLI. Mirrors the Java `Verifier` in `../src/main/java/com/example/xmlsec/Verifier.java`.

## Build & Run

```bash
cd python
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -v
```

```bash
python -m xmlsec_verify verify <sig_path_or_url> <keystore.p12>
```

Exit codes: 0 = valid, 1 = invalid, 2 = usage error.

## Structure

- `xmlsec_verify/verifier.py` — core verification logic
- `xmlsec_verify/__main__.py` — CLI entry point
- `tests/` — pytest suite; `conftest.py` loads shared fixtures from `data.xml`

## Key behaviours

- Accepts local path **or** `http(s)://` URL as signature source.
- Relative `<ds:Reference URI="...">` resolves against signature's parent directory (local) or base URL (HTTP).
- Password prompted via `getpass`; tests pass literal strings.
- Uses `signxml` + `cryptography`; no `xmlsec1` binary required.
