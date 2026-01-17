#!/usr/bin/env python3
"""
Request encrypted seed from instructor API
CRITICAL: Use the EXACT same GitHub repository URL that you'll submit!
"""
import requests
import json

# Configuration
STUDENT_ID = "23MH1A4236"
GITHUB_REPO_URL = "https://github.com/chandrabhanu18/Gpp_task2"
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

def request_seed(student_id: str, github_repo_url: str, api_url: str):
    """
    Request encrypted seed from instructor API
    
    Steps:
    1. Read student public key from PEM file
    2. Prepare HTTP POST request payload
    3. Send POST request to instructor API
    4. Parse JSON response
    5. Save encrypted seed to file
    """
    print("Step 1: Reading student public key...")
    try:
        with open("student_public.pem", "r") as f:
            public_key_pem = f.read()
        print("✓ Public key loaded")
    except FileNotFoundError:
        print("✗ Error: student_public.pem not found!")
        print("  Run generate_keys.py first to generate RSA keys")
        return
    
    print("\nStep 2: Preparing API request...")
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_pem
    }
    
    print(f"  Student ID: {student_id}")
    print(f"  Repository: {github_repo_url}")
    
    print("\nStep 3: Calling instructor API...")
    try:
        response = requests.post(
            api_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        response.raise_for_status()
        print(f"✓ API responded with status {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ API request failed: {e}")
        return
    
    print("\nStep 4: Parsing response...")
    try:
        data = response.json()
        
        if data.get("status") != "success":
            print(f"✗ API returned error: {data}")
            return
            
        encrypted_seed = data.get("encrypted_seed")
        if not encrypted_seed:
            print("✗ No encrypted_seed in response!")
            return
        
        print(f"✓ Received encrypted seed ({len(encrypted_seed)} characters)")
    except json.JSONDecodeError as e:
        print(f"✗ Failed to parse JSON response: {e}")
        return
    
    print("\nStep 5: Saving encrypted seed...")
    try:
        with open("encrypted_seed.txt", "w") as f:
            f.write(encrypted_seed)
        print("✓ Encrypted seed saved to encrypted_seed.txt")
        
        print("\n" + "="*60)
        print("SUCCESS! Encrypted seed obtained from instructor API")
        print("="*60)
        print("\nNext steps:")
        print("1. DO NOT commit encrypted_seed.txt to Git")
        print("2. Use this encrypted seed to test your /decrypt-seed endpoint")
        print("3. The decrypted seed must be exactly 64 hex characters")
        
    except Exception as e:
        print(f"✗ Failed to save encrypted seed: {e}")

if __name__ == "__main__":
    print("="*60)
    print("REQUESTING ENCRYPTED SEED FROM INSTRUCTOR API")
    print("="*60)
    print("\n⚠️  CRITICAL: This uses your student_public.pem to get")
    print("   the encrypted seed. The API encrypts a deterministic")
    print("   seed based on your student_id and github_repo_url.")
    print()
    
    request_seed(STUDENT_ID, GITHUB_REPO_URL, API_URL)
