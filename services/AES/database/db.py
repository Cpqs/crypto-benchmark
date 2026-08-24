import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "photos.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def save_photo(uuid: str, encrypted_photo: bytes, photo_hash: bytes):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO photos (
            uuid,
            encrypted_photo,
            photo_hash
        )
        VALUES (?, ?, ?)
        """,
        (
            uuid,
            encrypted_photo,
            photo_hash
        )
    )

    connection.commit()
    connection.close()



def get_photo(uuid: str):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT encrypted_photo, photo_hash
        FROM photos
        WHERE uuid = ?
        """,
        (uuid,)
    )

    result = cursor.fetchone()

    connection.close()

    return result



def save_key(uuid: str, key: bytes):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO keys (
            uuid,
            encryption_key
        )
        VALUES (?, ?)
        """,
        (
            uuid,
            key
        )
    )

    connection.commit()
    connection.close()



def get_key(uuid: str):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT encryption_key
        FROM keys
        WHERE uuid = ?
        """,
        (uuid,)
    )

    result = cursor.fetchone()

    connection.close()

    if result:
        return result[0]

    return None