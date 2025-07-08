from art import tprint

import database
import security


class Vault:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._encryption_key = None

        database.init_db(self.db_path)


def main() -> None:
    ...


if __name__ == "__main__":
    main()