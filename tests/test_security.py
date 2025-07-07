import pytest

from src.security import hash_password, verify_password, encrypt, decrypt

def test_hash_password():
    password = "my-simple-password"
    hashed_password = hash_password(password)
    assert verify_password(hashed_password, password) == True
    assert verify_password(hashed_password, "wrong-password") == False

def test_encrypt_decrypt():
    data = "this is my secret data"
    password = "my-simple-password"
    encrypted_data = encrypt(data, password)
    decrypted_data = decrypt(encrypted_data, password)
    assert decrypted_data == data

