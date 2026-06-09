"""HTTP-based verifier (mirrors HttpVerifyTest.java)."""

from __future__ import annotations

import shutil
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from xmlsec_verify import verify

DATA_SRC = Path(__file__).parent / "data.xml"


class _Handler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture
def http_server(tmp_path):
    handler = lambda *a, **kw: _Handler(*a, directory=str(tmp_path), **kw)  # noqa: E731
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}/", tmp_path
    finally:
        server.shutdown()
        server.server_close()


def _stage(serve_dir: Path, sign_detached) -> Path:
    payload = serve_dir / "data.xml"
    shutil.copy(DATA_SRC, payload)
    sig = serve_dir / "signed.xml"
    sig.write_bytes(sign_detached(payload))
    return payload


def test_verify_over_http_with_relative_uri(http_server, keystore_p12, sign_detached):
    base, serve_dir = http_server
    _stage(serve_dir, sign_detached)
    assert verify(f"{base}signed.xml", keystore_p12, "secret") is True


def test_tampered_payload_over_http_fails_verification(http_server, keystore_p12, sign_detached):
    base, serve_dir = http_server
    payload = _stage(serve_dir, sign_detached)
    payload.write_text(payload.read_text().replace("fubar", "TAMPERED"))
    assert verify(f"{base}signed.xml", keystore_p12, "secret") is False
