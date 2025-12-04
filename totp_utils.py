import base64
import pyotp


def _hex_seed_to_base32(hex_seed: str) -> str:
    """
    Convert 64-char hex seed -> Base32 string for TOTP
    """
    if len(hex_seed) != 64:
        raise ValueError("hex_seed must be a 64-character hex string")

    seed_bytes = bytes.fromhex(hex_seed)
    return base64.b32encode(seed_bytes).decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed
    """
    base32_seed = _hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with a time window
    """
    base32_seed = _hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)