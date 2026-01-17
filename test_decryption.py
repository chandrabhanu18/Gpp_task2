#!/usr/bin/env python3
"""
Test decryption of encrypted seed
"""
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def load_private_key():
    """Load student private key"""
    with open("student_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def decrypt_seed(encrypted_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP
    
    Critical Parameters:
    - Padding: OAEP (Optimal Asymmetric Encryption Padding)
    - MGF: MGF1 with SHA-256
    - Hash Algorithm: SHA-256
    - Label: None
    """
    # Step 1: Base64 decode
    ciphertext = base64.b64decode(encrypted_b64)
    
    # Step 2: RSA/OAEP decrypt with SHA-256
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Step 3: Decode bytes to UTF-8 string
    hex_seed = plaintext.decode('utf-8').strip().lower()
    
    # Step 4: Validate - must be 64-character hex string
    if len(hex_seed) != 64:
        raise ValueError(f"Invalid seed length: {len(hex_seed)} (expected 64)")
    
    if not all(c in '0123456789abcdef' for c in hex_seed):
        raise ValueError("Seed contains non-hex characters")
    
    # Step 5: Return hex seed
    return hex_seed

if __name__ == "__main__":
    print("Testing seed decryption...")
    print()
    
    # Load encrypted seed
    try:
        with open("encrypted_seed.txt", "r") as f:
            encrypted_seed = f.read().strip()
        print(f"✓ Loaded encrypted seed ({len(encrypted_seed)} chars)")
    except FileNotFoundError:
        print("✗ Error: encrypted_seed.txt not found!")
        print("  Run request_seed.py first")
        exit(1)
    
    # Load private key
    print("✓ Loading private key...")
    private_key = load_private_key()
    
    # Decrypt
    print("✓ Decrypting with RSA/OAEP-SHA256...")
    try:
        hex_seed = decrypt_seed(encrypted_seed, private_key)
        print(f"✓ Decryption successful!")
        print()
        print("Decrypted seed:")
        print(hex_seed)
        print()
        print(f"Length: {len(hex_seed)} characters")
        print(f"Format: {'Valid hex' if all(c in '0123456789abcdef' for c in hex_seed) else 'INVALID'}")
        
        # Save to test file
        with open("data/seed.txt", "w") as f:
            f.write(hex_seed)
        print()
        print("✓ Saved to data/seed.txt for testing")
        
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        exit(1)
