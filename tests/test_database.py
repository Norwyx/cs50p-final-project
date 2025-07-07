import sqlite3
from src import database
from src.security import hash_password


hashed_password = hash_password("test_password")


def test_set_master_password():
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.set_master_password(conn, hashed_password)
    assert database.get_master_password(conn) == hashed_password
    conn.close()


def test_get_master_password():
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.set_master_password(conn, hashed_password)
    assert database.get_master_password(conn) == hashed_password
    conn.close()