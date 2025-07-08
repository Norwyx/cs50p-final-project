from art import tprint
import sqlite3
import database
import security


DB_PATH = "vault.db"


class Vault:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._encryption_key = None
        database.init_db(self.conn)

    @property
    def is_locked(self) -> bool:
        return self._encryption_key is None

    def setup(self):
        if database.get_master_password(self.conn):
            return

        print("Please set a master password to secure your vault.")

        while True:
            password = input("Master Password: ")
            confirm_password = input("Confirm Master Password: ")

            if password == confirm_password:
                hashed_password = security.hash_password(password)
                database.set_master_password(self.conn, hashed_password)
                print("Master password set successfully!")
                break
            else:
                print("Passwords do not match. Please try again.")

    def lock(self):
        self._encryption_key = None

    def unlock(self):
        hashed_password = database.get_master_password(self.conn)

        while True:
            password = input("Enter Master Password: ")
            if security.verify_password(hashed_password, password):
                self._encryption_key = password
                print("Vault unlocked!")
                break
            else:
                print("Invalid password. Please try again.")

    def get_master_password(self):
        return database.get_master_password(self.conn)

    def change_master_password(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        old_password_hash = self.get_master_password()
        old_password = input("Enter old master password: ")

        if not security.verify_password(old_password_hash, old_password):
            print("Invalid old password.")
            return

        new_password = input("Enter new master password: ")
        confirm_password = input("Confirm new master password: ")

        if new_password == confirm_password:
            new_password_hash = security.hash_password(new_password)
            database.update_master_password(self.conn, new_password_hash)
            print("Master password updated successfully!")
        else:
            print("Passwords do not match.")

    def add_credential(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        service = input("Service: ")
        username = input("Username: ")
        password = input("Password: ")

        encrypted_password = security.encrypt(password, self._encryption_key)
        database.add_credential(self.conn, service, username, encrypted_password)
        print("Credential added successfully!")

    def get_credential(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        service = input("Service: ")
        credential = database.get_credential(self.conn, service)

        if credential:
            decrypted_password = security.decrypt(
                credential["encrypted_password"], self._encryption_key
            )
            print(f"Username: {credential['username']}")
            print(f"Password: {decrypted_password}")
        else:
            print("Credential not found.")

    def get_all_credentials(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        credentials = database.get_all_credentials(self.conn)

        for credential in credentials:
            print(f"Service: {credential['service']}")

    def update_credential(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        service = input("Service: ")
        new_username = input("New username: ")
        new_password = input("New password: ")

        encrypted_password = security.encrypt(new_password, self._encryption_key)
        database.update_credential(self.conn, service, new_username, encrypted_password)
        print("Credential updated successfully!")

    def delete_credential(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        service = input("Service: ")
        database.delete_credential(self.conn, service)
        print("Credential deleted successfully!")


def main():
    ...


if __name__ == "__main__":
    main()