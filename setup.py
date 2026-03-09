"""
One-time setup script. Run this ONCE before starting the app.
It generates encryption keys, creates .env, and sets up the initial admin account.

WARNING: Do not run this again — it will overwrite your keys and lock out all users.
"""
import json
import os
import re
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).parent
ENV_FILE = BASE_DIR / ".env"
USERS_FILE = BASE_DIR / "users.json"
DATA_FILE = BASE_DIR / "data.json"


def validate_password(password):
    errors = []
    if len(password) < 12:
        errors.append("Minimum 12 characters required.")
    if not re.search(r"[A-Z]", password):
        errors.append("Must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Must contain at least one digit.")
    if not re.search(r'[!@#$%^&*()\-_,.?\":{}|<>]', password):
        errors.append("Must contain at least one special character (!@#$%^&* etc).")
    return errors


def main():
    print("=== Medication Inventory — Setup ===\n")

    if ENV_FILE.exists():
        print("✓ .env already exists — reusing existing keys.\n")
        from dotenv import load_dotenv
        load_dotenv(ENV_FILE)
        encryption_key = os.environ["ENCRYPTION_KEY"]
    else:
        # Generate keys
        secret_key = secrets.token_hex(64)
        encryption_key = Fernet.generate_key().decode()
        ENV_FILE.write_text(
            f"SECRET_KEY={secret_key}\n"
            f"ENCRYPTION_KEY={encryption_key}\n"
        )
        print("✓ Generated SECRET_KEY and ENCRYPTION_KEY → .env")
        print("  IMPORTANT: Back up .env securely. If the ENCRYPTION_KEY is lost,")
        print("  all data is permanently unrecoverable.\n")

    fernet = Fernet(encryption_key.encode())

    # Create initial admin account
    print("Create the initial admin account:")
    username = input("  Admin username: ").strip()
    if not username:
        print("ERROR: Username cannot be empty.")
        ENV_FILE.unlink()
        sys.exit(1)

    while True:
        password = input("  Admin password (visible): ").strip()
        errors = validate_password(password)
        if errors:
            print("  Password does not meet requirements:")
            for e in errors:
                print(f"    - {e}")
            print("  Please try again.\n")
        else:
            confirm = input("  Confirm password: ").strip()
            if password != confirm:
                print("  Passwords do not match. Please try again.\n")
            else:
                break

    users = [{
        "username": username,
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
        "role": "admin",
        "active": True,
    }]

    # Encrypt and write users.json
    USERS_FILE.write_bytes(fernet.encrypt(json.dumps(users, indent=2).encode()))
    print(f"\n✓ Admin account '{username}' created → users.json (encrypted)")

    # Create empty encrypted data.json
    empty_data = {"inventory": [], "records": []}
    DATA_FILE.write_bytes(fernet.encrypt(json.dumps(empty_data, indent=2).encode()))
    print("✓ Initialized encrypted data store → data.json\n")

    print("Setup complete. Start the app with:")
    print("  python app.py\n")
    print("For production, use Gunicorn behind an HTTPS-terminating proxy:")
    print("  gunicorn app:app\n")


if __name__ == "__main__":
    main()
