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

        print()
        print("Please set a master password to secure your vault.")

        while True:
            password = input("Master Password: ")
            confirm_password = input("Confirm Master Password: ")

            if password == confirm_password:
                salt = security.generate_salt()
                hashed_password = security.hash_password(password)
                database.set_master_password(self.conn, hashed_password, salt)
                print("Master password set successfully!")
                print()
                break
            else:
                print("Passwords do not match. Please try again.")

    def lock(self):
        self._encryption_key = None

    def unlock(self):
        hashed_password, salt = database.get_master_password(self.conn)
        key = security._derive_key(hashed_password, salt)

        while True:
            password = input("Enter Master Password: ")
            if security.verify_password(hashed_password, password):
                self._encryption_key = key
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
            salt = security.generate_salt()
            new_password_hash = security.hash_password(new_password)
            database.update_master_password(self.conn, new_password_hash, salt)
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
        print()

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
            print()
            print(f"Username: {credential['username']}")
            print(f"Password: {decrypted_password}")
        else:
            print()
            print("Credential not found.")

    def get_all_credentials(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        credentials = database.get_all_credentials(self.conn)

        print()

        for credential in credentials:
            print(f"Service: {credential['service']}, Username: {credential['username']}, Password: {security.decrypt(credential['encrypted_password'], self._encryption_key)}")

    def update_credential(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        service = input("Service: ")
        new_username = input("New username: ")
        new_password = input("New password: ")
        print()

        encrypted_password = security.encrypt(new_password, self._encryption_key)
        database.update_credential(self.conn, service, new_username, encrypted_password)
        print("Credential updated successfully!")

    def delete_credential(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        service = input("Service: ")
        print()
        database.delete_credential(self.conn, service)
        print("Credential deleted successfully!")


def main() -> None:
    conn = database.get_db_connection(DB_PATH)
    vault = Vault(conn)

    user_name = database.get_user_name(conn)
    if user_name:
        tprint(f"Welcome back, {user_name}!", font="small")
    else:
        tprint("CS50P Vault", font="small")
        print()
        print("Welcome to the CS50P Vault! Let's get started.")
        print()
        name = input("What is your name? ").strip()
        database.set_user_name(conn, name)
        print(f"Welcome, {name}!")

    vault.setup()
    vault.unlock()

    while True:
        print_menu()
        print()
        choice = input("Enter your choice: ")

        if choice == "1":
            vault.add_credential()
        elif choice == "2":
            vault.get_credential()
        elif choice == "3":
            vault.get_all_credentials()
        elif choice == "4":
            vault.update_credential()
        elif choice == "5":
            vault.delete_credential()
        elif choice == "6":
            vault.change_master_password()
        elif choice == "7":
            vault.lock()
        elif choice == "8":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

    conn.close()


def print_menu() -> None:
    print("\nWhat would you like to do?")
    print("1. Add a credential")
    print("2. Get a credential")
    print("3. Get all credentials")
    print("4. Update a credential")
    print("5. Delete a credential")
    print("6. Change master password")
    print("7. Lock vault")
    print("8. Exit")


if __name__ == "__main__":
    main()