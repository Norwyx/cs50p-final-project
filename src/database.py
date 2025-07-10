import sqlite3


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """
    Establishes a connection to the SQLite database and configures the row factory.

    This function connects to the database file specified by `db_path` and sets the
    `row_factory` to `sqlite3.Row`. This allows accessing columns by name, making
    the code more readable and less prone to errors.

    Args:
        db_path: The file path to the SQLite database.

    Returns:
        A `sqlite3.Connection` object connected to the database.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """
    Initializes the database by creating necessary tables if they do not already exist.

    This function creates three tables:
    - `master_password`: Stores the hashed master password, its salt, and the key salt.
    - `credentials`: Stores the service name, username, and encrypted password for each entry.
    - `user`: Stores the user's name.

    Args:
        conn: The `sqlite3.Connection` object for database interaction.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            key_salt TEXT NOT NULL
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


# CRUD functions for master password


def set_master_password(conn: sqlite3.Connection, hashed_password: str, salt: bytes, key_salt: bytes) -> None:
    """
    Saves the initial master password details to the database.

    This function should only be called during the initial setup of the vault.

    Args:
        conn: The `sqlite3.Connection` object.
        hashed_password: The master password after being hashed.
        salt: The salt used for hashing the master password.
        key_salt: The salt used for deriving the encryption key.
    """
    conn.execute(
        "INSERT INTO master_password (hashed_password, salt, key_salt) VALUES (?, ?, ?)",
        (hashed_password, salt, key_salt),
    )
    conn.commit()


def get_master_password(conn: sqlite3.Connection) -> tuple[str, bytes, bytes] | None:
    """
    Retrieves the master password details from the database.

    Args:
        conn: The `sqlite3.Connection` object.

    Returns:
        A tuple containing the hashed password, its salt, and the key salt,
        or `None` if no master password has been set.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password, salt, key_salt FROM master_password")
    result = cursor.fetchone()
    return result if result else None


def update_master_password(conn: sqlite3.Connection, hashed_password: str, salt: bytes, key_salt: bytes) -> None:
    """
    Updates the existing master password details in the database.

    Args:
        conn: The `sqlite3.Connection` object.
        hashed_password: The new master password after being hashed.
        salt: The new salt for hashing.
        key_salt: The new salt for key derivation.
    """
    conn.execute(
        "UPDATE master_password SET hashed_password = ?, salt = ?, key_salt = ? WHERE id = 1",
        (hashed_password, salt, key_salt),
    )
    conn.commit()


# CRUD functions for credentials


def add_credential(conn: sqlite3.Connection, service: str, username: str, encrypted_password: bytes) -> None:
    """
    Adds a new encrypted credential to the database.

    Args:
        conn: The `sqlite3.Connection` object.
        service: The name of the service (e.g., 'Google', 'GitHub').
        username: The username for the service.
        encrypted_password: The password for the service, already encrypted.
    """
    conn.execute(
        "INSERT INTO credentials (service, username, encrypted_password) VALUES (?, ?, ?)",
        (service, username, encrypted_password),
    )
    conn.commit()


def get_credential(conn: sqlite3.Connection, service: str) -> tuple | None:
    """
    Retrieves a specific credential from the database by its service name.

    Args:
        conn: The `sqlite3.Connection` object.
        service: The name of the service to retrieve.

    Returns:
        A tuple containing the service, username, and encrypted password,
        or `None` if the service is not found.
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
    Retrieves all stored credentials from the database.

    Args:
        conn: The `sqlite3.Connection` object.

    Returns:
        A list of tuples, where each tuple represents a credential
        (service, username, encrypted_password).
    """
    cursor = conn.cursor()
    cursor.execute("SELECT service, username, encrypted_password FROM credentials")
    result = cursor.fetchall()
    return result


def update_credential(conn: sqlite3.Connection, service: str, new_username: str, new_encrypted_password: bytes) -> None:
    """
    Updates an existing credential in the database.

    Args:
        conn: The `sqlite3.Connection` object.
        service: The service whose credential is to be updated.
        new_username: The new username for the service.
        new_encrypted_password: The new encrypted password for the service.
    """
    conn.execute(
        "UPDATE credentials SET username = ?, encrypted_password = ? WHERE service = ?",
        (new_username, new_encrypted_password, service),
    )
    conn.commit()


def delete_credential(conn: sqlite3.Connection, service: str) -> None:
    """
    Deletes a credential from the database by its service name.

    Args:
        conn: The `sqlite3.Connection` object.
        service: The name of the service to delete.
    """
    conn.execute("DELETE FROM credentials WHERE service = ?", (service,))
    conn.commit()


# CRUD functions for user


def set_user_name(conn: sqlite3.Connection, name: str) -> None:
    """
    Saves or updates the user's name in the database.

    Args:
        conn: The `sqlite3.Connection` object.
        name: The user's name to be saved.
    """
    conn.execute(
        "INSERT OR REPLACE INTO user (id, name) VALUES (1, ?)",
        (name,),
    )
    conn.commit()


def get_user_name(conn: sqlite3.Connection) -> str | None:
    """
    Retrieves the user's name from the database.

    Args:
        conn: The `sqlite3.Connection` object.

    Returns:
        The user's name as a string, or `None` if no name has been set.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM user WHERE id = 1")
    result = cursor.fetchone()
    return result[0] if result else None
