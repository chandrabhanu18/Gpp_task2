#!/usr/bin/env python3
# Cron script to log 2FA codes every minute

import os
import sys
from datetime import datetime, timezone

# Make sure we can import totp_utils from /app
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = os.path.dirname(SCRIPT_DIR)
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

from totp_utils import generate_totp_code

DATA_SEED_PATH = "/data/seed.txt"


def read_seed():
    if not os.path.exists(DATA_SEED_PATH):
        return None
    try:
        with open(DATA_SEED_PATH, "r") as f:
            return f.read().strip()
    except Exception:
        return None


def main():
    seed = read_seed()
    if not seed:
        print("No seed found")
        return

    # Generate TOTP code
    try:
        code = generate_totp_code(seed)
    except Exception as e:
        print("Error generating code:", e)
        return

    # Get current UTC timestamp (no pytz needed)
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%d %H:%M:%S")

    # Format: "[timestamp] - 2FA Code: {code}"
    line = f"[{ts}] - 2FA Code: {code}"
    print(line)


if __name__ == "__main__":
    main()