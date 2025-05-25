#!/usr/bin/env python3
"""
Generate secure secret keys for SecureNet SOC Platform
"""

import secrets
import string
import os

def generate_secret_key(length=64):
    """Generate a cryptographically secure random key"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_flask_secret_key():
    """Generate Flask-compatible secret key"""
    return secrets.token_hex(32)

def generate_jwt_secret():
    """Generate JWT secret key"""
    return secrets.token_urlsafe(64)

if __name__ == "__main__":
    print("🔐 SecureNet SOC Platform - Secret Key Generator")
    print("=" * 50)
    
    flask_secret = generate_flask_secret_key()
    jwt_secret = generate_jwt_secret()
    
    print("\n✅ Generated Secure Keys:")
    print(f"\nFLASK_SECRET_KEY={flask_secret}")
    print(f"JWT_SECRET_KEY={jwt_secret}")
    
    print("\n📋 Copy these keys to your .env file:")
    print(f"SECRET_KEY={flask_secret}")
    print(f"JWT_SECRET_KEY={jwt_secret}")
    
    print("\n🔒 Security Notes:")
    print("- These keys are cryptographically secure")
    print("- Never share these keys publicly")
    print("- Use different keys for production")
    print("- Regenerate keys if compromised")
