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


def encrypt(data: str, password: str) -> bytes:
    """
    Encrypts data with a key derived from the password.
    The salt is prepended to the ciphertext.
    """
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    encrypted_data = Fernet(key).encrypt(data.encode())
    return salt + encrypted_data


def decrypt(token: bytes, password: str) -> str:
    """
    Decrypts data with a key derived from the password.
    Salt has to be prepended to the ciphertext.
    """
    salt = token[:16]
    encrypted_data = token[16:]
    key = _derive_key(password, salt)
    decrypted_data = Fernet(key).decrypt(encrypted_data).decode()
    return decrypted_data
