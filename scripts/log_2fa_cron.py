#!/usr/bin/env python3
import sys
from datetime import datetime, timezone
from pathlib import Path
import string, base64
import pyotp

SEED_FILE = Path("/data/seed.txt")

def generate_totp_code(hex_seed: str) -> str:
    if len(hex_seed) != 64 or any(c not in string.hexdigits.lower() for c in hex_seed):
        raise ValueError("Not valid 64-char hex seed")
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8")
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()

def main():
    if not SEED_FILE.exists():
        print("No seed found", file=sys.stderr)
        return

    try:
        hex_seed = SEED_FILE.read_text().strip().lower()
        code = generate_totp_code(hex_seed)
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts} - 2FA Code: {code}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
