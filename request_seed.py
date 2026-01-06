import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

STUDENT_ID = "23MH1A4236"
REPO_URL = "https://github.com/chandrabhanu18/Gpp_task2"
COMMIT_HASH = "a8294c5fb6446f29a1d2d37893e092b3444d290b"

# 1. Generate expected seed (same logic as evaluator)
seed_material = STUDENT_ID + REPO_URL + COMMIT_HASH
seed = hashlib.sha256(seed_material.encode()).hexdigest()

print("Expected seed:")
print(seed)

# 2. Load STUDENT PUBLIC KEY  ✅ (THIS IS THE FIX)
with open("student_public.pem", "rb") as f:
    student_pub = serialization.load_pem_public_key(f.read())

# 3. Encrypt seed with STUDENT public key
encrypted = student_pub.encrypt(
    seed.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

encrypted_b64 = base64.b64encode(encrypted).decode()

# 4. Write encrypted seed
with open("encrypted_seed.txt", "w") as f:
    f.write(encrypted_b64)

print("\nEncrypted seed written to encrypted_seed.txt")
