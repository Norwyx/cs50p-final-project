import base64
import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hashes a password for storage and verification."""
    return ph.hash(password)


def verify_password(hashed_password: str, password: str) -> bool:
    """Verifies a password against a stored hash."""
    try:
        ph.verify(hashed_password, password)
        return True
    except VerifyMismatchError:
        return False


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

