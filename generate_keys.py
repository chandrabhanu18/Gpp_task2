#!/usr/bin/env python3
"""
Generate RSA 4096-bit key pair for student
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size=4096):
    """Generate RSA key pair with specified key size"""
    print(f"Generating {key_size}-bit RSA key pair...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

if __name__ == "__main__":
    private_pem, public_pem = generate_rsa_keypair(4096)
    
    # Save private key
    with open("student_private.pem", "wb") as f:
        f.write(private_pem)
    print("✓ Saved student_private.pem")
    
    # Save public key
    with open("student_public.pem", "wb") as f:
        f.write(public_pem)
    print("✓ Saved student_public.pem")
    
    print("\n⚠️  WARNING: These keys will be PUBLIC in your repository!")
    print("   DO NOT reuse them for any other purpose!")
