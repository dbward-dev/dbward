#!/usr/bin/env python3
"""Generate test Ed25519 license keys for E2E testing.

Usage:
  python3 dev/scripts/generate-test-license.py [--expired]

Output:
  - dev/testdata/licenses/test.pub.hex   (public key hex, for DBWARD_LICENSE_PUBLIC_KEY)
  - dev/testdata/licenses/pro.key        (valid Pro license key)
  - dev/testdata/licenses/expired.key    (expired Pro license key)
"""
import base64
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("pip install cryptography", file=sys.stderr)
    sys.exit(1)

OUT_DIR = Path(__file__).resolve().parent.parent / "testdata" / "licenses"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Generate or load keypair
KEY_FILE = OUT_DIR / "test.secret.bin"
if KEY_FILE.exists():
    private_key = Ed25519PrivateKey.from_private_bytes(KEY_FILE.read_bytes())
else:
    private_key = Ed25519PrivateKey.generate()
    KEY_FILE.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    KEY_FILE.chmod(0o600)

public_key_bytes = private_key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
pub_hex = public_key_bytes.hex()

# Write public key
(OUT_DIR / "test.pub.hex").write_text(pub_hex + "\n")


def make_license(plan: str, expires_at: datetime) -> str:
    payload = {
        "key_id": f"test-{plan}",
        "plan": plan,
        "issued_to": "e2e-test",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    payload_bytes = json.dumps(payload).encode()
    payload_b64 = base64.b64encode(payload_bytes).decode()
    signature = private_key.sign(payload_bytes)
    sig_b64 = base64.b64encode(signature).decode()
    return f"dbward_lic_v1.{payload_b64}.{sig_b64}"


# Pro license (valid for 1 year)
pro_key = make_license("pro", datetime.now(timezone.utc) + timedelta(days=365))
(OUT_DIR / "pro.key").write_text(pro_key + "\n")

# Expired license
expired_key = make_license("pro", datetime.now(timezone.utc) - timedelta(days=1))
(OUT_DIR / "expired.key").write_text(expired_key + "\n")

print(f"Generated test licenses in {OUT_DIR}")
print(f"  Public key (hex): {pub_hex}")
print(f"  Pro key:     {OUT_DIR / 'pro.key'}")
print(f"  Expired key: {OUT_DIR / 'expired.key'}")
print()
print("To use in docker-compose:")
print(f"  DBWARD_LICENSE_PUBLIC_KEY={pub_hex}")
print(f"  DBWARD_LICENSE_KEY=$(cat {OUT_DIR / 'pro.key'})")
