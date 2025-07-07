import sqlite3

def get_db_connection():
    '''
    Returns a connection to the database.
    '''
    conn = sqlite3.connect('vault.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    '''
    Initializes the database by creating the master_password and credentials tables if they don't exist.
    '''
    conn = get_db_connection()

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

def set_master_password(hashed_password: str) -> None:
    conn = get_db_connection()
    
    conn.execute('INSERT INTO master_password (hashed_password) VALUES (?)', (hashed_password,))
    
    conn.commit()
    conn.close()


def get_master_password() -> str:
    conn = get_db_connection()
    
    master_password = conn.execute('SELECT hashed_password FROM master_password').fetchone()
    
    conn.close()
    return master_password


def update_master_password(hashed_password: str) -> None:
    conn = get_db_connection()
    
    conn.execute('UPDATE master_password SET hashed_password = ?', (hashed_password,))
    
    conn.commit()
    conn.close()




