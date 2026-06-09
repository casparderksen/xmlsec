"""Test fixtures: PKCS#12 keystore + detached-signature helper.

Mirrors src/test/java/com/example/xmlsec/TestKeystore.java parameters
(alias=mykey, password=secret, RSA-2048, SHA256withRSA self-signed).
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import DigestAlgorithm, SignatureMethod, XMLSigner, methods

ALIAS = "mykey"
PASSWORD = "secret"


@pytest.fixture(scope="session")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(int(now.timestamp() * 1000))
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture(scope="session")
def keystore_p12(tmp_path_factory, keypair):
    key, cert = keypair
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=ALIAS.encode(),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode()),
    )
    path = tmp_path_factory.mktemp("ks") / "keystore.p12"
    path.write_bytes(p12_bytes)
    return path


@pytest.fixture
def sign_detached(keypair):
    """Sign `payload_path` with a detached XMLDSig referencing its filename.

    The returned signature has `<ds:Reference URI="<basename>">` and is
    intended to be written next to the payload so relative resolution works.
    """
    key, cert = keypair
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    def _sign(payload_path: Path) -> bytes:
        signer = XMLSigner(
            method=methods.detached,
            signature_algorithm=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        )
        signed = signer.sign(
            payload_path.read_bytes(),
            key=key_pem,
            cert=cert_pem,
            reference_uri=payload_path.name,
        )
        return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")

    return _sign
