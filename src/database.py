import sqlite3

def get_db_connection(db_path: str) -> sqlite3.Connection:
    '''
    Returns a connection to the database.
    '''
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str):
    '''
    Initializes the database by creating the master_password and credentials tables if they don't exist.
    '''
    conn = get_db_connection(db_path)

    conn.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            hashed_password TEXT NOT NULL)
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            service TEXT NOT NULL, 
            username TEXT NOT NULL, 
            encrypted_password BLOB NOT NULL)
    ''')

    conn.commit()
    conn.close()




#CRUD functions for master password

def set_master_password(db_path: str, hashed_password: str) -> None:
    conn = get_db_connection(db_path)
    
    conn.execute('INSERT INTO master_password (hashed_password) VALUES (?)', (hashed_password,))
    
    conn.commit()
    conn.close()


def get_master_password(db_path: str) -> str:
    conn = get_db_connection(db_path)
    
    master_password = conn.execute('SELECT hashed_password FROM master_password WHERE id = 1').fetchone()
    
    conn.close()
    return master_password


def update_master_password(db_path: str, hashed_password: str) -> None:
    conn = get_db_connection(db_path)
    
    conn.execute('UPDATE master_password SET hashed_password = ? WHERE id = 1', (hashed_password,))
    
    conn.commit()
    conn.close()




#CRUD functions for credentials

def add_credential(db_path: str, service: str, username: str, encrypted_password: bytes) -> None:
    """
    Adds a new credential to the database.
    """
    conn = get_db_connection(db_path)
    
    conn.execute('''
        INSERT INTO credentials (service, username, encrypted_password) 
        VALUES (?, ?, ?)
        ''', (service, username, encrypted_password))
    
    conn.commit()
    conn.close()


def get_credential(db_path: str, service: str) -> tuple:
    """
    Retrieves a credential from the database.
    """
    conn = get_db_connection(db_path)
    
    credential = conn.execute('SELECT * FROM credentials WHERE service = ?', (service,)).fetchone()
    
    conn.close()
    return credential


def get_all_credentials(db_path: str) -> list:
    """
    Retrieves all credentials from the database.
    """
    conn = get_db_connection(db_path)

    credentials = conn.execute('SELECT * FROM credentials').fetchall()
    
    conn.close()
    return credentials


def update_credential(db_path: str, service: str, new_username: str, new_encrypted_password: bytes) -> None:
    """
    Updates a credential in the database.
    """
    conn = get_db_connection(db_path)
    
    conn.execute('''
        UPDATE credentials 
        SET username = ?, encrypted_password = ? WHERE service = ?
        ''', (new_username, new_encrypted_password, service))
    
    conn.commit()
    conn.close()


def delete_credential(db_path: str, service: str) -> None:
    """
    Deletes a credential from the database.
    """
    conn = get_db_connection(db_path)

    conn.execute('DELETE FROM credentials WHERE service = ?', (service,))
    conn.commit()
    conn.close()