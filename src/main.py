from art import tprint
import getpass
import sqlite3
import database
import security
from rich.console import Console
from rich.table import Table
import pyperclip
import os
import time


DB_PATH = "vault.db"
console = Console()


class Vault:
    """
    Manages the vault operations, including setup, locking/unlocking, and credential management.

    Attributes:
        conn (sqlite3.Connection): The database connection object.
        _encryption_key (bytes | None): The encryption key derived from the master password,
                                        used for encrypting and decrypting credentials.
    """
    def __init__(self, conn: sqlite3.Connection):
        """
        Initializes the Vault with a database connection.

        Args:
            conn (sqlite3.Connection): The database connection object.
        """
        self.conn = conn
        self._encryption_key = None
        database.init_db(self.conn)

    @property
    def is_locked(self) -> bool:
        """
        Checks if the vault is currently locked.

        Returns:
            bool: True if the vault is locked (no encryption key), False otherwise.
        """
        return self._encryption_key is None

    def setup(self):
        """
        Guides the user through setting up a master password if one doesn't exist.

        This function prompts the user to create and confirm a master password.
        It hashes the password and generates a salt for both password hashing
        and key derivation, then stores them in the database.
        """
        if database.get_master_password(self.conn):
            return

        print()
        print("Please set a master password to secure your vault.")

        while True:
            password = getpass.getpass("Master Password: ")
            confirm_password = getpass.getpass("Confirm Master Password: ")

            if password == confirm_password:
                salt = security.generate_salt()
                key_salt = security.generate_salt()
                hashed_password = security.hash_password(password)
                database.set_master_password(self.conn, hashed_password, salt, key_salt)
                print("Master password set successfully!")
                print()
                break
            else:
                print("Passwords do not match. Please try again.")

    def lock(self):
        """
        Locks the vault by clearing the encryption key.

        This makes all credential operations unavailable until the vault is unlocked again.
        """
        self._encryption_key = None

    def unlock(self):
        """
        Unlocks the vault by verifying the master password and deriving the encryption key.

        Prompts the user for the master password and verifies it against the stored hash.
        If successful, it derives the encryption key and sets the vault to an unlocked state.
        """
        master_password_data = database.get_master_password(self.conn)
        if not master_password_data:
            return
        
        hashed_password, _, key_salt = master_password_data

        while True:
            password = getpass.getpass("Enter Master Password: ")
            if security.verify_password(hashed_password, password):
                self._encryption_key = security.derive_key(password, key_salt)
                console.print("\n[bold green]Vault unlocked![/bold green]")
                break
            else:
                console.print("\n[bold red]Error:[/bold red] Invalid password. Please try again.\n")

    def get_master_password(self):
        """
        Retrieves the master password data from the database.

        Returns:
            tuple[str, bytes, bytes] | None: A tuple containing the hashed password,
                                            its salt, and the key salt, or None if not set.
        """
        return database.get_master_password(self.conn)

    def change_master_password(self):
        """
        Allows the user to change the master password.

        Requires the vault to be unlocked. Prompts for the old password for verification,
        then prompts for a new password and its confirmation. If valid, updates the
        hashed password, salts, and encryption key in the database.
        """
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        master_password_data = self.get_master_password()
        if not master_password_data:
            console.print("\n[bold red]Error:[/bold red] No master password set.\n")
            return
        
        old_password_hash, _, _ = master_password_data
        old_password = getpass.getpass("Enter old master password: ")

        if not security.verify_password(old_password_hash, old_password):
            console.print("\n[bold red]Error:[/bold red] Invalid old password.\n")
            return

        new_password = getpass.getpass("Enter new master password: ")
        confirm_password = getpass.getpass("Confirm new master password: ")

        if new_password == confirm_password:
            salt = security.generate_salt()
            key_salt = security.generate_salt()
            new_password_hash = security.hash_password(new_password)
            database.update_master_password(self.conn, new_password_hash, salt, key_salt)
            console.print("\n[bold green]Master password updated successfully![/bold green]\n")
        else:
            console.print("\n[bold red]Error:[/bold red] Passwords do not match.\n")

    def add_credential(self):
        """
        Adds a new credential (service, username, password) to the vault.

        Requires the vault to be unlocked. Prompts the user for service, username,
        and password, then encrypts the password and stores it in the database.
        """
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        service = input("Service: ")
        username = input("Username: ")
        password = getpass.getpass("Password: ")

        encrypted_password = security.encrypt(password, self._encryption_key)
        database.add_credential(self.conn, service, username, encrypted_password)
        console.print("\n[bold green]Credential added successfully![/bold green]")

    def get_credential(self):
        """
        Retrieves and displays a specific credential, copying the password to the clipboard.

        Requires the vault to be unlocked. Prompts for the service name, retrieves the
        credential from the database, decrypts the password, displays the username,
        and copies the password to the clipboard.
        """
        if self.is_locked:
            console.print("\n[bold red]Error:[/bold red] Please unlock the vault first.")
            return

        service = input("Service: ")
        credential = database.get_credential(self.conn, service)

        if credential:
            decrypted_password = security.decrypt(
                credential["encrypted_password"], self._encryption_key
            )
            
            console.print(f"Username: {credential['username']}")
            pyperclip.copy(decrypted_password)
            console.print("[bold green]Password copied to clipboard.[/bold green]")
            time.sleep(5)
            clear_screen()
        else:
            console.print("[bold red]Credential not found.[/bold red]")

    def get_all_credentials(self):
        """
        Retrieves and displays all stored credentials.

        Requires the vault to be unlocked. Fetches all credentials from the database
        and displays their service, username, and a masked representation of the password.
        """
        if self.is_locked:
            console.print("Please unlock the vault first.")
            return

        credentials = database.get_all_credentials(self.conn)

        if credentials:
            for credential in credentials:
                console.print(f"[bold]Service[/bold]: {credential['service']}, [bold]Username[/bold]: {credential['username']}, [bold]Password[/bold]: {len(security.decrypt(credential['encrypted_password'], self._encryption_key)) * '*'}")
            console.print("\nIf you want to get an specific password, use option 2 instead.")
        else:
            console.print("[bold red]No credentials found.[/bold red]")

    def update_credential(self):
        """
        Updates an existing credential in the vault.

        Requires the vault to be unlocked. Prompts for the service name, new username,
        and new password. Encrypts the new password and updates the credential in the database.
        """
        if self.is_locked:
            console.print("Please unlock the vault first.")
            return

        service = input("Service: ")
        new_username = input("New username: ")
        new_password = getpass.getpass("New password: ")
        print()

        encrypted_password = security.encrypt(new_password, self._encryption_key)
        database.update_credential(self.conn, service, new_username, encrypted_password)
        console.print("[bold green]Credential updated successfully![/bold green]")

    def delete_credential(self):
        """
        Deletes a credential from the vault.

        Requires the vault to be unlocked. Prompts for the service name and deletes
        the corresponding credential from the database.
        """
        if self.is_locked:
            console.print("Please unlock the vault first.")
            return

        service = input("Service: ")
        console.print()
        database.delete_credential(self.conn, service)
        console.print("[bold green]Credential deleted successfully![/bold green]")


def main() -> None:
    """
    Main function to run the CS50P Vault application.

    Establishes a database connection, initializes the Vault, handles user setup
    and authentication, and then enters the main application loop to process user commands.
    """
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
        console.print(f"Welcome, {name}!")

    vault.setup()
    vault.unlock()
    clear_screen()

    while True:
        clear_screen()
        print_menu()
        console.print()
        choice = input("Enter your choice: ")
        console.print()

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
            clear_screen()
            console.print("Vault locked.")
            time.sleep(2)
            
        elif choice == "8":
            console.print("Goodbye!")
            console.print()
            break
        else:
            console.print("Invalid choice. Please try again.")

    conn.close()


def print_menu() -> None:
    """
    Displays the main menu in a formatted table using rich.
    """
    table = Table(title="[bold cyan]CS50P Vault Menu[/bold cyan]", show_header=True, header_style="bold magenta")

    table.add_column("Option", style="dim", width=12)
    table.add_column("Action")

    table.add_row("[bold]1[/bold]", "Add a new credential")
    table.add_row("[bold]2[/bold]", "Get a credential")
    table.add_row("[bold]3[/bold]", "List all credentials")
    table.add_row("[bold]4[/bold]", "Update a credential")
    table.add_row("[bold]5[/bold]", "Delete a credential")
    table.add_row("", "") 
    table.add_row("[bold]6[/bold]", "Change master password")
    table.add_row("[bold]7[/bold]", "Lock vault")
    table.add_row("[bold]8[/bold]", "Exit")

    console.print()
    console.print(table)  


def clear_screen() -> None:
    """
    Clears the terminal screen.
    
    This function checks the operating system and uses the appropriate
    command ('cls' for Windows, 'clear' for macOS/Linux).
    """
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


if __name__ == "__main__":
    main()