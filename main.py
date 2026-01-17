from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import pyotp
import sys
from datetime import datetime, timezone
from pathlib import Path

# Persistent storage path for seed
SEED_FILE = Path("/data/seed.txt")

app = FastAPI(title="Secure PKI - TOTP 2FA Microservice", version="1.0")

HEX_CHARS = set("0123456789abcdef")


class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str | None = None


# Load RSA private key
def load_private_key():
    """Load student private key from PEM file"""
    try:
        with open("student_private.pem", "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(), 
                password=None, 
                backend=default_backend()
            )
        return key
    except Exception as e:
        print(f"Failed to load private key: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Private key unavailable")


# Decrypt seed with RSA/OAEP-SHA256
def decrypt_seed(encrypted_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP
    
    Critical Parameters:
    - Padding: OAEP
    - MGF: MGF1 with SHA-256
    - Hash Algorithm: SHA-256
    - Label: None
    """
    try:
        # Step 1: Base64 decode
        ciphertext = base64.b64decode(encrypted_b64)
        
        # Step 2: RSA/OAEP decrypt with SHA-256
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
        
        # Step 3: Decode bytes to UTF-8 string
        seed = plaintext.decode("utf-8").strip().lower()

        # Step 4: Validate 64-char lowercase hex
        if len(seed) != 64 or any(c not in HEX_CHARS for c in seed):
            raise ValueError("Invalid seed format")

        return seed

    except Exception as e:
        print(f"Decryption error: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Decryption failed")


# Generate TOTP code
def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed
    
    Implementation:
    1. Convert hex seed to bytes
    2. Convert bytes to base32 encoding
    3. Create TOTP object (SHA-1, 30s period, 6 digits)
    4. Generate current code
    """
    try:
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode("utf-8")
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
        return totp.now()
    except Exception as e:
        print(f"TOTP generation error: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="TOTP generation failed")


# Verify TOTP with ±1 period tolerance
def verify_totp_code(hex_seed: str, code: str) -> bool:
    """
    Verify TOTP code with time window tolerance
    
    Args:
        hex_seed: 64-character hex string
        code: 6-digit code to verify
        valid_window: 1 = ±30 seconds tolerance
    """
    try:
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode("utf-8")
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


# Calculate remaining seconds in current period
def seconds_left(interval: int = 30) -> int:
    """Calculate remaining seconds in current TOTP period"""
    now = int(time.time())
    return interval - (now % interval)


# --- API ENDPOINTS ---

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(payload: DecryptSeedRequest):
    """
    POST /decrypt-seed
    
    Request: {"encrypted_seed": "BASE64_STRING..."}
    Response (200): {"status": "ok"}
    Response (500): {"error": "Decryption failed"}
    """
    private_key = load_private_key()
    
    try:
        hex_seed = decrypt_seed(payload.encrypted_seed, private_key)
    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Decryption failed")

    # Save to persistent storage
    SEED_FILE.parent.mkdir(parents=True, exist_ok=True)
    SEED_FILE.write_text(hex_seed + "\n", encoding="utf-8")

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa_endpoint():
    """
    GET /generate-2fa
    
    Response (200): {"code": "123456", "valid_for": 30}
    Response (500): {"error": "Seed not decrypted yet"}
    """
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    try:
        hex_seed = SEED_FILE.read_text(encoding="utf-8").strip().lower()
    except Exception as e:
        print(f"Seed file read error: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Seed unreadable")

    code = generate_totp_code(hex_seed)
    valid_for = seconds_left(30)

    return {"code": code, "valid_for": valid_for}


@app.post("/verify-2fa")
def verify_2fa_endpoint(payload: VerifyRequest):
    """
    POST /verify-2fa
    
    Request: {"code": "123456"}
    Response (200): {"valid": true/false}
    Response (400): {"error": "Missing code"}
    Response (500): {"error": "Seed not decrypted yet"}
    """
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

    # Validate code format
    if len(code) != 6 or not code.isdigit():
        return {"valid": False}

    result = verify_totp_code(hex_seed, code)
    return {"valid": result}


@app.get("/health")
def health_check():
    """Health check endpoint for container readiness"""
    return {"status": "ok"}


