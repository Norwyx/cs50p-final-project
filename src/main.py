from art import tprint

import database
import security


class Vault:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._encryption_key = None

        database.init_db(self.db_path)

    
    def is_locked(self) -> bool:
        return self._encryption_key is None

    
    def setup(self) -> None:
        master_password = input("Enter a master password: ")
        hashed_password = security.hash_password(master_password)
        database.set_master_password(self.db_path, hashed_password) 
        self._encryption_key = security._derive_key(master_password, b"")   
    

    def lock(self) -> None:
        self._encryption_key = None
        print("Vault locked.")
    
    
    def unlock(self) -> None:
        master_password = input("Enter your master password: ")
        hashed_password = security.hash_password(master_password)
        if security.verify_password(hashed_password, master_password):
            self._encryption_key = security._derive_key(master_password, b"")
        else:
            print("Incorrect master password.")

    
    def add_credential(self) -> None:
        if self.is_locked():
            print("Vault is locked. Please unlock first.")
            return
        
        service = input("Enter the service name: ")
        username = input("Enter the username: ")
        password = input("Enter the password: ")
        encrypted_password = security.encrypt(password, self._encryption_key)
        database.add_credential(self.db_path, service, username, encrypted_password)

    
    def get_credential(self) -> None:
        if self.is_locked():
            print("Vault is locked. Please unlock first.")
            return
        
        service = input("Enter the service name: ")
        credential = database.get_credential(self.db_path, service)
        if credential:
            print(f"Service: {credential['service']}")
            print(f"Username: {credential['username']}")
            print(f"Password: {security.decrypt(credential['encrypted_password'], self._encryption_key)}")
        else:
            print("Credential not found.")
    
    
    def get_all_credentials(self) -> None:
        if self.is_locked():
            print("Vault is locked. Please unlock first.")
            return
        
        credentials = database.get_all_credentials(self.db_path)
        for credential in credentials:
            print(f"Service: {credential['service']}")
            print(f"Username: {credential['username']}")
            print(f"Password: {security.decrypt(credential['encrypted_password'], self._encryption_key)}")
    

    def update_credential(self) -> None:
        if self.is_locked():
            print("Vault is locked. Please unlock first.")
            return
        
        service = input("Enter the service name: ")
        new_username = input("Enter the new username: ")
        new_password = input("Enter the new password: ")
        encrypted_password = security.encrypt(new_password, self._encryption_key)
        database.update_credential(self.db_path, service, new_username, encrypted_password)


    def delete_credential(self) -> None:
        if self.is_locked():
            print("Vault is locked. Please unlock first.")
            return
        
        service = input("Enter the service name: ")
        database.delete_credential(self.db_path, service)


def main() -> None:
    ...


if __name__ == "__main__":
    main()