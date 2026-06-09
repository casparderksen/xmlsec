# xmlsec PoC

Detached XML Digital Signature generator + validator built on Apache Santuario. Output is compatible with `xmlsec1`.

> PoC only — do not pass passwords on the command line or store them in files in production.

## Build

```bash
mvn package
```

Produces fat jar `target/xmlsec-poc.jar` and runs the JUnit test suite.

```bash
mvn test          # tests only
mvn package -DskipTests
```

## Generate test material

```bash
# RSA keypair + self-signed cert
openssl genrsa -out key.pem 2048
openssl req -new -x509 \
    -key key.pem \
    -out cert.pem \
    -days 365 \
    -subj "/CN=Test"

# PKCS12 keystore (alias "mykey", password "secret")
openssl pkcs12 -export \
    -inkey key.pem \
    -in cert.pem \
    -out keystore.p12 \
    -name mykey
```

## Sign / verify with Java

Keystore password is prompted interactively — never passed on the command line.

```bash
java -jar target/xmlsec-poc.jar sign data.xml signed2.xml keystore.p12
# Keystore password: ********

java -jar target/xmlsec-poc.jar verify signed2.xml keystore.p12
# Keystore password: ********

java -jar target/xmlsec-poc.jar --help
java -jar target/xmlsec-poc.jar sign --help
```

Requires a TTY; running with redirected stdin will fail with "No interactive console available".

## Sign / verify with xmlsec1

```bash
# uses signature.xml as template
xmlsec1 --sign --privkey-pem:mykey key.pem --output signed.xml signature.xml
xmlsec1 --verify --pubkey-cert-pem:mykey cert.pem signed.xml
```

## Cross-tool verification

`xmlsec1` should accept Java-signed output, and Java should accept xmlsec1-signed output:

```bash
xmlsec1 --verify --pubkey-cert-pem:mykey cert.pem signed2.xml
java -jar target/xmlsec-poc.jar verify signed.xml keystore.p12
```

Formatting differs (Java omits whitespace inside `<ds:SignedInfo>`); signature semantics are identical.

## How detached signatures work

A detached signature is stored separately from the content it covers. The `<ds:Reference>` element inside the signature file carries a URI pointing to the signed content:

```xml
<ds:Reference URI="data.xml">
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  <ds:DigestValue>...</ds:DigestValue>
</ds:Reference>
```

The signature covers `<ds:SignedInfo>`, which contains both the `<ds:Reference>` URI and the digest. This means two things are cryptographically bound:

- **Content integrity** — the digest value ensures the bytes at the URI have not changed since signing.
- **Reference identity** — the URI string itself is part of the signed data, so it cannot be swapped out after the fact.

### Portability via relative URIs

This tool writes a relative URI (e.g. `data.xml`) rather than an absolute filesystem path. The verifier resolves it relative to the location of the signature file, so the signature–payload pair can be moved or copied anywhere and verification still works. An absolute path like `/home/user/projects/xmlsec/data.xml` would break the moment the files were relocated.

### Generalizing to HTTP

Because the URI scheme is irrelevant to the cryptographic operations, the same mechanism works over HTTP. Replacing `URI="data.xml"` with `URI="https://example.com/document.xml"` produces a signature that a verifier can check by fetching the document over the network. Apache Santuario supports this via pluggable `ResourceResolver` implementations; no changes to the signing or verification logic are required.
