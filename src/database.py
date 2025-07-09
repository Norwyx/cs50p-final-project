import sqlite3

def get_db_connection(db_path: str) -> sqlite3.Connection:
    '''
    Returns a connection to the database.
    '''
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn: sqlite3.Connection) -> None:
    """
    Initializes the database by creating the master_password and credentials tables if they don't exist.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        """
    )
    conn.commit()




#CRUD functions for master password

def set_master_password(conn: sqlite3.Connection, hashed_password: str, salt: bytes) -> None:
    conn.execute(
        "INSERT INTO master_password (hashed_password, salt) VALUES (?, ?)", (hashed_password, salt)
    )
    conn.commit()


def get_master_password(conn: sqlite3.Connection) -> tuple[str, bytes] | None:
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password, salt FROM master_password")
    result = cursor.fetchone()
    return result if result else None


def update_master_password(conn: sqlite3.Connection, hashed_password: str, salt: bytes) -> None:
    conn.execute(
        "UPDATE master_password SET hashed_password = ?, salt = ? WHERE id = 1",
        (hashed_password, salt),
    )
    conn.commit()




#CRUD functions for credentials

def add_credential(
    conn: sqlite3.Connection, service: str, username: str, encrypted_password: bytes
) -> None:
    """
    Adds a new credential to the database.
    """
    conn.execute(
        "INSERT INTO credentials (service, username, encrypted_password) VALUES (?, ?, ?)",
        (service, username, encrypted_password),
    )
    conn.commit()


def get_credential(conn: sqlite3.Connection, service: str) -> tuple | None:
    """
    Retrieves a credential from the database.
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT service, username, encrypted_password FROM credentials WHERE service = ?",
        (service,),
    )
    result = cursor.fetchone()
    return result


def get_all_credentials(conn: sqlite3.Connection) -> list[tuple]:
    """
    Retrieves all credentials from the database.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT service, username, encrypted_password FROM credentials")
    result = cursor.fetchall()
    return result


def update_credential(
    conn: sqlite3.Connection, service: str, new_username: str, new_encrypted_password: bytes
) -> None:
    """
    Updates a credential in the database.
    """
    conn.execute(
        "UPDATE credentials SET username = ?, encrypted_password = ? WHERE service = ?",
        (new_username, new_encrypted_password, service),
    )
    conn.commit()


def delete_credential(conn: sqlite3.Connection, service: str) -> None:
    """
    Deletes a credential from the database.
    """
    conn.execute("DELETE FROM credentials WHERE service = ?", (service,))
    conn.commit()


# CRUD functions for user
def set_user_name(conn: sqlite3.Connection, name: str) -> None:
    """Saves the user's name to the database."""
    conn.execute(
        "INSERT OR REPLACE INTO user (id, name) VALUES (1, ?)",
        (name,),
    )
    conn.commit()


def get_user_name(conn: sqlite3.Connection) -> str | None:
    """Retrieves the user's name from the database."""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM user WHERE id = 1")
    result = cursor.fetchone()
    return result[0] if result else None