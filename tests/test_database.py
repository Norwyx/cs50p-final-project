import sqlite3
from src import database
from src.security import hash_password


hashed_password = hash_password("test_password")


def test_set_and_get_master_password():
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.set_master_password(conn, hashed_password)
    assert database.get_master_password(conn) == hashed_password
    conn.close()


def test_update_master_password():
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.set_master_password(conn, hashed_password)
    database.update_master_password(conn, hashed_password)
    assert database.get_master_password(conn) == hashed_password
    conn.close()


def test_add_and_get_credential():
    conn = database.get_db_connection(":memory:")
    database.init_db(conn)
    database.add_credential(conn, "test_service", "test_username", hashed_password)
    assert tuple(database.get_credential(conn, "test_service")) == (
        "test_service",
        "test_username",
        hashed_password,
    )
    conn.close()    