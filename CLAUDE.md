# CLAUDE.md

## Goal

Proof-of-concept: generate + validate detached XML Digital Signatures compatible with `xmlsec1` CLI. Built on **Apache Santuario** — JSR 105 abandoned because it can't produce xmlsec1-style `ds:`-prefixed output.

## Build & Run

```bash
mvn package        # tests + fat jar
mvn test
mvn package -DskipTests
java -jar target/xmlsec-poc.jar sign   <payload.xml> <signature.xml> <keystore.p12>
java -jar target/xmlsec-poc.jar verify <signature.xml> <keystore.p12>
```

Password **prompted via `System.console().readPassword`** — never on CLI. No TTY → "No interactive console available". Tests call `Signer`/`Verifier` directly with literal password.

## xmlsec1 reference commands

```bash
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=Test"
openssl pkcs12 -export -inkey key.pem -in cert.pem -out keystore.p12 -name mykey

xmlsec1 --sign --privkey-pem:mykey key.pem --output signed.xml signature.xml
xmlsec1 --verify --pubkey-cert-pem:mykey cert.pem signed.xml
```

## xmlsec1 compatibility constraints

- Detached: `<ds:Reference URI="...">` relative to signature file's directory.
- Algorithms: C14N 1.0 inclusive, RSA-SHA256, SHA-256 digest.
- `<ds:KeyInfo>` must carry `<ds:KeyName>mykey</ds:KeyName>`.
- Namespace prefix must be `ds:` (not default namespace).
- **Never reformat `<ds:SignedInfo>` after signing** — whitespace is part of the signed C14N.

## Gotchas

- **Don't use template-driven signing** (`XMLSignature(Element, baseURI)` constructor is verification-only; `sign()` NPEs because references aren't indexed).
- Output has no whitespace inside `<ds:SignedInfo>` — programmatic API can't inject it. Visually differs from xmlsec1 pretty output but semantically equivalent.
- Sandboxed shells deny reads on `**/*.p12` / `**/*.pem`; manual smoke testing requires running outside sandbox.
- xmlsec1 parity tested manually from shell only — never from Java tests.
