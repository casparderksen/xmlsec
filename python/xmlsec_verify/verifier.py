"""Detached XMLDSig verifier with relative-URI resolution.

Mirrors src/main/java/com/example/xmlsec/Verifier.java. Accepts a signature
from a local path or HTTP URL; relative `<ds:Reference URI=...>` values are
resolved against the signature's parent directory or base URL.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)
from signxml import XMLVerifier
from signxml.exceptions import InvalidDigest, InvalidInput, InvalidSignature


def verify(source: str | Path, p12_path: Path, password: str) -> bool:
    """Return True iff signature at `source` verifies against the cert in `p12_path`."""
    source_str = str(source)
    if _is_http(source_str):
        sig_bytes = requests.get(source_str, timeout=30).content
        base_uri = _parent_url(source_str)
    else:
        sig_path = Path(source_str).resolve()
        sig_bytes = sig_path.read_bytes()
        base_uri = sig_path.parent.as_uri() + "/"

    cert_pem = _load_cert_pem(Path(p12_path), password)
    resolver = _make_resolver(base_uri)

    try:
        XMLVerifier().verify(
            sig_bytes,
            x509_cert=cert_pem,
            uri_resolver=resolver,
            expect_references=1,
        )
    except (InvalidSignature, InvalidDigest, InvalidInput):
        return False
    return True


def _is_http(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def _parent_url(url: str) -> str:
    # Strip the last path segment, keep trailing slash.
    parsed = urlparse(url)
    path = parsed.path.rsplit("/", 1)[0] + "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _load_cert_pem(p12_path: Path, password: str) -> bytes:
    _, cert, _ = load_key_and_certificates(p12_path.read_bytes(), password.encode())
    if cert is None:
        raise ValueError(f"No certificate in {p12_path}")
    return cert.public_bytes(Encoding.PEM)


def _make_resolver(base_uri: str):
    def resolve(uri: str):
        target = uri if urlparse(uri).scheme else urljoin(base_uri, uri)
        scheme = urlparse(target).scheme
        if scheme in ("http", "https"):
            data = requests.get(target, timeout=30).content
        elif scheme == "file":
            data = Path(urlparse(target).path).read_bytes()
        else:
            raise ValueError(f"Unsupported URI scheme for ref: {target}")
        return data
    return resolve
