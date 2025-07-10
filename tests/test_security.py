from src.security import hash_password, verify_password, encrypt, decrypt, derive_key, generate_salt

def test_hash_password():
    """
    Tests the `hash_password` and `verify_password` functions.

    This test ensures that a password can be correctly hashed and then verified
    against its hash, and that an incorrect password fails verification.
    """
    password = "my-simple-password"
    hashed_password = hash_password(password)
    assert verify_password(hashed_password, password) == True
    assert verify_password(hashed_password, "wrong-password") == False

def test_encrypt_decrypt():
    """
    Tests the `encrypt` and `decrypt` functions.

    This test verifies that data can be encrypted using a derived key and then
    successfully decrypted back to its original form.
    """
    data = "this is my secret data"
    password = "my-simple-password"
    salt = generate_salt()
    key = derive_key(password, salt)
    encrypted_data = encrypt(data, key)
    decrypted_data = decrypt(encrypted_data, key)
    assert decrypted_data == data

