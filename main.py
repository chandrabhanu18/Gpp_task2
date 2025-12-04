import os
import time
import base64
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

# For local testing on Windows, keep it relative.
# In Docker they will mount /data, you can change it there.
DATA_SEED_PATH = "data/seed.txt"


# ---------- RSA PRIVATE KEY LOADING ----------

def load_private_key(path: str = "student_private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


# ---------- SEED VALIDATION + CONVERSION ----------

def _validate_hex_seed(hex_seed: str):
    if len(hex_seed) != 64:
        raise ValueError("Seed must be 64 characters")
    hex_chars = "0123456789abcdefABCDEF"
    if not all(c in hex_chars for c in hex_seed):
        raise ValueError("Seed must be hexadecimal")


def _hex_seed_to_base32(hex_seed: str) -> str:
    _validate_hex_seed(hex_seed)
    seed_bytes = bytes.fromhex(hex_seed)
    base32_bytes = base64.b32encode(seed_bytes)
    return base32_bytes.decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    base32_seed = _hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    base32_seed = _hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return bool(totp.verify(code, valid_window=valid_window))


def load_hex_seed_from_file() -> str:
    with open(DATA_SEED_PATH, "r") as f:
        hex_seed = f.read().strip()
    _validate_hex_seed(hex_seed)
    return hex_seed


# ---------- FastAPI app ----------

app = FastAPI()


class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class Verify2FARequest(BaseModel):
    code: str


# Endpoint 1: POST /decrypt-seed
@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(body: DecryptSeedRequest):
    try:
        # 1. Load private key
        private_key = load_private_key("student_private.pem")

        # 2. Base64 decode
        encrypted_bytes = base64.b64decode(body.encrypted_seed)

        # 3. RSA OAEP SHA-256 decrypt
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 4. Bytes -> string (hex seed) + validate
        hex_seed = decrypted_bytes.decode("utf-8").strip()
        _validate_hex_seed(hex_seed)

        # 5. Save to data/seed.txt
        os.makedirs(os.path.dirname(DATA_SEED_PATH), exist_ok=True)
        with open(DATA_SEED_PATH, "w") as f:
            f.write(hex_seed)

        # 6. Success response
        return {"status": "ok"}

    except Exception:
        # any error => 500 with required message
        return JSONResponse(
            status_code=500,
            content={"error": "Decryption failed"}
        )


# Endpoint 2: GET /generate-2fa
@app.get("/generate-2fa")
async def generate_2fa():
    # 1. Check seed file
    if not os.path.exists(DATA_SEED_PATH):
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"}
        )

    try:
        # 2. Read hex seed
        hex_seed = load_hex_seed_from_file()

        # 3. Generate code
        code = generate_totp_code(hex_seed)

        # 4. Calculate remaining seconds in this 30s window
        interval = 30
        now = int(time.time())
        valid_for = interval - (now % interval)   # 1–30

        return {"code": code, "valid_for": valid_for}

    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"}
        )


# Endpoint 3: POST /verify-2fa
@app.post("/verify-2fa")
async def verify_2fa(body: Optional[Verify2FARequest] = None):
    # 1. Validate code field
    if body is None or not body.code:
        return JSONResponse(
            status_code=400,
            content={"error": "Missing code"}
        )

    # 2. Check seed file
    if not os.path.exists(DATA_SEED_PATH):
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"}
        )

    try:
        # 3. Read seed
        hex_seed = load_hex_seed_from_file()

        # 4. Verify with ±1 period
        is_valid = verify_totp_code(hex_seed, body.code, valid_window=1)

        # 5. Return result
        return {"valid": bool(is_valid)}

    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"}
        )