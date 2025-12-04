from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
import base64, time, string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import pyotp
import sys
from datetime import datetime, timezone
from pathlib import Path
from pathlib import Path
SEED_FILE = Path("/data/seed.txt")

app = FastAPI(title="Secure PKI - TOTP 2FA Microservice", version="1.0")

HEX_CHARS = set("0123456789abcdef")


class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str | None = None


# Load your RSA private key
def load_private_key():
    try:
        with open("student_private.pem", "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        return key
    except Exception as e:
        print(f"Failed to load private key: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Private key unavailable")


# Decrypt seed with RSA/OAEP-SHA256
def decrypt_seed(encrypted_b64: str, private_key) -> str:
    try:
        cipher = base64.b64decode(encrypted_b64)
        plain = private_key.decrypt(
            cipher,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
        seed = plain.decode("utf-8").strip().lower()

        # Validate 64-char lowercase hex
        if len(seed) != 64 or any(c not in HEX_CHARS for c in seed):
            raise ValueError("Invalid seed format")

        return seed

    except Exception as e:
        print(f"Decryption error: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Decryption failed")


# Generate TOTP code
def generate_totp_code(hex_seed: str) -> str:
    try:
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode("utf-8")

        totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
        return totp.now()
    except Exception:
        raise HTTPException(status_code=500, detail="TOTP generation failed")


# Verify TOTP ±1 period
def verify_totp_code(hex_seed: str, code: str) -> bool:
    try:
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode("utf-8")
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


# Remaining seconds left
def seconds_left(interval: int = 30) -> int:
    now = int(time.time())
    return interval - (now % interval)


# --- API ENDPOINTS ---

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: DecryptSeedRequest):
    private_key = load_private_key()
    try:
        hex_seed = decrypt_seed(payload.encrypted_seed, private_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")

    SEED_FILE.parent.mkdir(parents=True, exist_ok=True)
    SEED_FILE.write_text(hex_seed + "\n", encoding="utf-8")

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa_endpoint():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        hex_seed = SEED_FILE.read_text(encoding="utf-8").strip().lower()
    except Exception as e:
        print(f"Seed file read error: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Seed unreadable")

    code = generate_totp_code(hex_seed)  # throws 500 if it fails

    valid_for = seconds_left(30)

    # Optional extra cron log fallback (keeps the service robust)
    cron_log_dir = Path("/cron")
    cron_log_dir.mkdir(parents=True, exist_ok=True)
    try:
        with open("/cron/last_code.txt", "a", encoding="utf-8", newline="\n") as f:
            utc_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{utc_timestamp} - 2FA Code: {code}\n")
    except Exception as e:
        print(f"Failed to write cron log fallback: {e}", file=sys.stderr)

    return {"code": code, "valid_for": valid_for}


@app.post("/verify-2fa")
def verify_2fa_endpoint(payload: VerifyRequest):
    if payload.code is None:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        hex_seed = SEED_FILE.read_text(encoding="utf-8").strip().lower()
    except Exception as e:
        print(f"Seed file read error: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Seed unreadable")

    code = payload.code.strip()

    # Validate code input
    if len(code) != 6 or not code.isdigit():
        return {"valid": False}

    result = verify_totp_code(hex_seed, code)
    return {"valid": result}


@app.get("/health")
def health_check():
    return {"status": "ok"}
