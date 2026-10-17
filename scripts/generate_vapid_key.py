"""Create a new private VAPID PEM; stdout contains only the public browser key.

Run with ``python -m scripts.generate_vapid_key --output local_data/security/vapid.pem``.
Existing files are never opened or overwritten. This command does not read
application settings, load .env, contact providers or enable notifications.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.app.private_storage import create_private_file, prepare_private_directory


def generate_vapid_key(output: str | Path) -> dict[str, str]:
    """Persist a new P-256 secret privately, then return its public key only."""
    destination = Path(output)
    prepare_private_directory(destination.parent)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Exclusive creation protects existing keys; permissions apply before any
    # PEM bytes are written, including on Windows with inherited broad ACLs.
    with create_private_file(destination) as stream:
        stream.write(pem)
        stream.flush()
        os.fsync(stream.fileno())
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return {"public_key": base64.urlsafe_b64encode(public).decode("ascii").rstrip("=")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output", required=True, type=Path, help="New private P-256 PEM file")
    args = parser.parse_args(argv)
    try:
        result = generate_vapid_key(args.output)
    except (OSError, ValueError):
        print("Cannot create a new private VAPID key. Use a private directory and a new filename.", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
