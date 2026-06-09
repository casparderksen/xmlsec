"""File-based verifier round-trip (mirrors SignVerifyTest.java)."""

from __future__ import annotations

import shutil
from pathlib import Path

from xmlsec_verify import verify

DATA_SRC = Path(__file__).parent / "data.xml"


def _stage(tmp_path: Path, sign_detached) -> tuple[Path, Path]:
    payload = tmp_path / "data.xml"
    shutil.copy(DATA_SRC, payload)
    sig = tmp_path / "signed.xml"
    sig.write_bytes(sign_detached(payload))
    return sig, payload


def test_sign_produces_verifiable_signature(tmp_path, keystore_p12, sign_detached):
    sig, _ = _stage(tmp_path, sign_detached)
    assert verify(sig, keystore_p12, "secret") is True


def test_tampered_payload_fails_verification(tmp_path, keystore_p12, sign_detached):
    sig, payload = _stage(tmp_path, sign_detached)
    payload.write_text(payload.read_text().replace("fubar", "TAMPERED"))
    assert verify(sig, keystore_p12, "secret") is False
