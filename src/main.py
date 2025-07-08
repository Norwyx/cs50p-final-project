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


def main() -> None:
    ...


if __name__ == "__main__":
    main()