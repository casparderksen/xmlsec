# XML Digital Signature Demo

Detached XML Digital Signature generator + validator in Java built on Apache Santuario. 
Output is compatible with `xmlsec1`. Python verifier based on `signxml`.

## Build

```bash
mvn package
```

Produces fat jar `target/xmlsec-poc.jar` and runs the JUnit test suite.

```bash
mvn test                # tests only
mvn package -DskipTests # package only
```

## Tests

Signing an verification is validated via automated tests. Each test gets a fresh PKCS#12 keystore generated at runtime (`TestKeystore`) — no key material is checked in.

### `SignVerifyTest` — file I/O round-trip

- **`signProducesVerifiableSignature`** — sign `data.xml`, then verify the output. Happy path.
- **`tamperedPayloadFailsVerification`** — sign, mutate the payload on disk, re-verify. Confirms the detached digest catches payload tampering.
- **`outputUsesDsPrefixAndExpectedAlgorithms`** — parses the signature DOM and asserts the xmlsec1 wire-format constraints: `ds:` prefix on `Signature`, `rsa-sha256` `SignatureMethod`, `sha256` `DigestMethod`, relative `Reference URI="data.xml"`, and non-blank `DigestValue` / `SignatureValue`.

### `HttpVerifyTest` — HTTP resolution

Spins up a loopback `HttpServer` per test serving the temp workspace, and mirrors the served files into `target/http-test-downloads/<testName>/` so they can be inspected after the run.

- **`verifyOverHttpWithRelativeUri`** — sign, serve `signed.xml` + `data.xml`, verify via `http://127.0.0.1:<port>/signed.xml`. Exercises `Verifier.verify(URL, ...)` and confirms relative-URI resolution against the signature's HTTP base URL.
- **`tamperedPayloadOverHttpFailsVerification`** — same flow with the payload mutated post-sign; verification must fail.

### Not covered by automated tests

- xmlsec1 CLI parity — manual only (see "Cross-tool verification" below).
- CLI entrypoint and interactive password prompt.
- Wrong-key / missing-alias / expired-cert failure modes.

## Generate test material

```bash
# RSA keypair + self-signed cert
openssl genrsa -out key.pem 2048
openssl req -new -x509 \
    -key key.pem \
    -out cert.pem \
    -days 365 \
    -subj "/CN=Test"

# PKCS12 keystore (alias "mykey")
openssl pkcs12 -export \
    -inkey key.pem \
    -in cert.pem \
    -out keystore.p12 \
    -name mykey
```

## Sign / verify with Java

Keystore password is prompted interactively — never passed on the command line.

```bash
java -jar target/xmlsec-poc.jar sign data.xml signed.xml keystore.p12
java -jar target/xmlsec-poc.jar verify signed.xml keystore.p12
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

### Sign with xmlsec1, verify with Java

```bash
xmlsec1 --sign --privkey-pem:mykey key.pem --output signed.xml signature.xml
java -jar target/xmlsec-poc.jar verify signed.xml keystore.p12
```

### Sign with Java, verify with xmlsec1

```bash
java -jar target/xmlsec-poc.jar sign data.xml signed.xml keystore.p12
xmlsec1 --verify --pubkey-cert-pem:mykey cert.pem signed.xml
```

Formatting differs (Java omits whitespace inside `<ds:SignedInfo>`); signature semantics are identical.

### Sign with Java, verify with python

See [python/README.md](python/README.md) for building the Python signature verification tool.

```bash
java -jar target/xmlsec-poc.jar sign data.xml signed.xml keystore.p12\n
python/.venv/bin/python -m xmlsec_verify verify signed.xml keystore.p12
```

## Digital signatures

An XML Digital Signature (XMLDSig, W3C standard) cryptographically binds a signature to one or more content items. A valid signature proves two things:

- **Content integrity** — the signed content has not been modified since it was signed. XMLDSig signs the output of a **canonicalization** transform (C14N, W3C XML Canonicalization), not raw file bytes. C14N normalizes the XML so semantically equivalent documents produce identical octets (fixed attribute order, UTF-8, normalized whitespace). Any change to those canonical octets invalidates the signature; changes that canonicalize to the same output (e.g. reordered attributes) do not.
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

Verification checks two things: the digest inside `<ds:Reference>` must match the octets produced by dereferencing the URI and applying the `Reference`'s declared `Transforms` (with no `Transforms`, the raw bytes at the URI), and the signature over the canonicalized `<ds:SignedInfo>` must verify with the signer's public key (signer identity).

Two C14N applications are in play and should not be confused: `CanonicalizationMethod` (child of `SignedInfo`) canonicalizes `SignedInfo` itself before `SignatureValue` is computed and always applies; a C14N transform inside `<ds:Reference><ds:Transforms>` canonicalizes the referenced payload before digesting and is optional, typically used when the payload is XML and whitespace or attribute-order tolerance is wanted.

The URI appears inside `<ds:SignedInfo>` because that is the atomic unit XMLDSig signs — the spec defines `SignedInfo` to contain the `Reference` elements, each holding a URI and its digest.

Two distinct bindings flow from this:

- **URI binding** — the URI string itself is signed. An in-place edit of `URI="data.xml"` to another value invalidates the signature, because the `SignedInfo` octets change.
- **Content binding** — `DigestValue` cryptographically commits to the bytes the URI resolves to. Substituting the bytes at the resolved location (without touching the signature file) is caught by digest comparison, not by URI binding.

Both are required: URI binding alone would not stop payload tampering, and digest binding alone would let an attacker repoint the reference at a colliding file.



### Portability via relative URIs

If a detached signature uses a relative URI (e.g. `data.xml`) rather than an absolute location, verification is independent of storage location — the location is resolved relative to the signature URI, so the pair can be moved or copied anywhere. An absolute location like `/files/data.xml` would break the moment the files were relocated.

A relative URI is safe **against payload tampering**: the digest in `SignedInfo` is signed, so substituted bytes at the resolved location fail verification. It does **not** bind the signature to a specific protocol, location, or moment in time. Properties the signature does not provide on its own:

- **Location/filename semantics** — identical bytes served from a different directory still verify. If the filename itself carries meaning, that meaning must be encoded inside the signed payload.
- **Freshness / replay protection** — an old signed pair can be re-presented later. Mitigate inside the payload (timestamp, nonce, monotonic counter).
- **Base-URI consistency** — relative resolution depends on the verifier's chosen base (signature-file directory vs. process CWD vs. HTTP base URL). Portability assumes a verifier that resolves against the signature file's location.

### Generalizing to HTTP

Because the URI scheme is irrelevant to the cryptographic operations, the same mechanism works over HTTP. A relative URI like `data.xml` resolves against the base URL of the signature file — if the signature is served from `https://example.com/signed.xml`, the payload is fetched from `https://example.com/data.xml`. Apache Santuario supports this via pluggable `ResourceResolver` implementations; no changes to the signing or verification logic are required.

Crypto guarantees carry over unchanged, but URI dereferencing over the network introduces attack surface absent from local-file verification. See "Risks & mitigation" below.

### Risks & mitigation

A verifier that dereferences `Reference URI` over the network — especially one that accepts signature files from untrusted sources — should defend against the following. The cryptographic check is necessary but not sufficient.

- **SSRF (Server-Side Request Forgery)** — attacker-supplied `URI` is dereferenced from the verifier's network position. Signature fails, but the request already happened — and may have hit internal services, triggered side-effects, or returned cloud metadata credentials. Mitigations: scheme + host allowlist; block RFC1918, link-local, loopback; bound redirects, size, timeout.
- **TOCTOU (Time-Of-Check to Time-Of-Use)** — verifier digests bytes fetched at T; application re-fetches at T+Δ and consumes different bytes. Mitigation: fetch once, verify and consume the same in-memory buffer.
- **Denial of service** — payload may be unreachable, slow, huge, or an infinite stream. Mitigations: timeouts, response-size cap, bounded redirects.
- **XXE / entity expansion** — parse fetched XML with a hardened parser (DTDs and external entities disabled, `FEATURE_SECURE_PROCESSING` on); otherwise attacker payload can read local files or blow up memory before signature check runs.
- **Privacy leak** — every fetch reveals verifier IP, TLS fingerprint, and timing to the URI's host, even when verification fails. Mitigations: controlled egress proxy, or URI allowlist.

## AI Disclosure

This project uses artificial intelligence tools for research, coding, or documentation. All final content
was  reviewed, edited, and validated by the human author before publication.
