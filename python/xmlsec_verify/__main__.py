"""CLI: python -m xmlsec_verify verify <sig_path_or_url> <keystore.p12>"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

from .verifier import verify


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != "verify":
        print("usage: python -m xmlsec_verify verify <sig_path_or_url> <keystore.p12>",
              file=sys.stderr)
        return 2
    _, source, p12 = argv
    password = getpass.getpass("Keystore password: ")
    ok = verify(source, Path(p12), password)
    print("OK" if ok else "INVALID")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
