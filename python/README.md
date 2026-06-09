# Python verifier

Detached XMLDSig verifier with relative-URI resolution. Mirrors the Java verifier in `src/main/java/com/example/xmlsec/Verifier.java`.

## Install & test

```bash
cd python
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -v
```

## CLI

```bash
python -m xmlsec_verify verify <sig_path_or_url> <keystore.p12>
# Keystore password: ********
```

Exit 0 = valid, 1 = invalid, 2 = usage error. Source accepts a local path or `http(s)://` URL; relative `<ds:Reference URI="...">` resolves against the signature's parent directory or base URL.

## Cross-tool verification

Verify a signature produced by the Java signer or `xmlsec1`:

```bash
java -jar ../target/xmlsec-poc.jar sign data.xml signed.xml keystore.p12
python -m xmlsec_verify verify signed.xml keystore.p12
```
