from art import tprint
import getpass
import sqlite3
import database
import security
from rich.console import Console
from rich.table import Table
import pyperclip


DB_PATH = "vault.db"
console = Console()


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
            password = getpass.getpass("Master Password: ")
            confirm_password = getpass.getpass("Confirm Master Password: ")

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
            password = getpass.getpass("Enter Master Password: ")
            if security.verify_password(hashed_password, password):
                self._encryption_key = key
                console.print("\n[bold green]Vault unlocked![/bold green]")
                break
            else:
                console.print("\n[bold red]Error:[/bold red] Invalid password. Please try again.\n")

    def get_master_password(self):
        return database.get_master_password(self.conn)

    def change_master_password(self):
        if self.is_locked:
            print("Please unlock the vault first.")
            return

        old_password_hash = self.get_master_password()
        old_password = getpass.getpass("Enter old master password: ")

        if not security.verify_password(old_password_hash, old_password):
            console.print("\n[bold red]Error:[/bold red] Invalid old password.\n")
            return

        new_password = getpass.getpass("Enter new master password: ")
        confirm_password = getpass.getpass("Confirm new master password: ")

        if new_password == confirm_password:
            salt = security.generate_salt()
            new_password_hash = security.hash_password(new_password)
            database.update_master_password(self.conn, new_password_hash, salt)
            console.print("\n[bold green]Master password updated successfully![/bold green]\n")
        else:
            console.print("\n[bold red]Error:[/bold red] Passwords do not match.\n")

    def add_credential(self):
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
        else:
            console.print("[bold red]Credential not found.[/bold red]")

    def get_all_credentials(self):
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
        if self.is_locked:
            console.print("Please unlock the vault first.")
            return

        service = input("Service: ")
        console.print()
        database.delete_credential(self.conn, service)
        console.print("[bold green]Credential deleted successfully![/bold green]")


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
        console.print(f"Welcome, {name}!")

    vault.setup()
    vault.unlock()

    while True:
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


if __name__ == "__main__":
    main()