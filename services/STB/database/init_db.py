import sqlite3
from pathlib import Path


def init_db():
    DB_PATH = Path(__file__).resolve().parent / "photos.db"


    if DB_PATH.exists():
        DB_PATH.unlink()


    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()


    cursor.execute("""
    CREATE TABLE photos (
        uuid TEXT PRIMARY KEY,
        encrypted_photo BLOB NOT NULL,
        photo_hash BLOB NOT NULL
    )
    """)


    cursor.execute("""
    CREATE TABLE keys (
        uuid TEXT PRIMARY KEY,
        encryption_key BLOB NOT NULL
    )
    """)


    connection.commit()
    connection.close()