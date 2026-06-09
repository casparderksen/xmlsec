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

## Digital signatures

An XML Digital Signature (XMLDSig, W3C standard) cryptographically binds a signature to one or more content items. A valid signature proves two things:

- **Content integrity** — the signed content has not been modified since it was signed. Any change to the bytes, however small, invalidates the signature.
- **Signer identity** — the signature was produced by the holder of a specific private key. When that key is accompanied by an X.509 certificate issued by a trusted authority, the verifier can establish *who* signed the content, not just *that* someone signed it.

### Signature placement

XMLDSig supports three ways to position the signature relative to the content it covers:

- **Enveloping** — the signed content is embedded *inside* the `<ds:Signature>` element, under a `<ds:Object>` child. The signature wraps the data.
- **Enveloped** — the `<ds:Signature>` element is embedded *inside* the document being signed. Common for signing entire XML documents such as SOAP messages or SAML assertions.
- **Detached** — the signature lives in a separate file and references the content via URI. The payload and the signature file are independent artifacts that can be stored, transferred, and verified separately.

This PoC uses detached signatures.

## How detached signatures work

A detached signature is stored separately from the content it covers. The `<ds:Reference>` element inside the signature file carries a URI pointing to the signed content:

```xml
<ds:Reference URI="data.xml">
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  <ds:DigestValue>...</ds:DigestValue>
</ds:Reference>
```

Verification checks two things: the digest inside `<ds:Reference>` must match the bytes at the URI (content integrity), and the signature over `<ds:SignedInfo>` must verify with the signer's public key (signer identity). The URI appears inside `<ds:SignedInfo>` because that is the atomic unit XMLDSig signs — the spec defines `SignedInfo` to contain the `Reference` elements, each holding a URI and its digest. Because the URI is part of `SignedInfo`, an attacker cannot redirect the signature to a different file — changing `URI="data.xml"` to point elsewhere invalidates the signature. 



### Portability via relative URIs

If a detached signature uses a relative URI (e.g. `data.xml`) rather than an absolute filesystem path, verification is independent of storage location — the path is resolved relative to the signature file, so the pair can be moved or copied anywhere. An absolute path like `/home/user/projects/xmlsec/data.xml` would break the moment the files were relocated.
A relative URI like `data.xml` is safe because the payload is cryptographically signed.

### Generalizing to HTTP

Because the URI scheme is irrelevant to the cryptographic operations, the same mechanism works over HTTP. A relative URI like `data.xml` resolves against the base URL of the signature file — if the signature is served from `https://example.com/signed.xml`, the payload is fetched from `https://example.com/data.xml`. Apache Santuario supports this via pluggable `ResourceResolver` implementations; no changes to the signing or verification logic are required.
