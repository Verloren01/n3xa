import hashlib
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("database.db")


def login(usuario: str, password: str):
    """Valida un usuario usando un hash de la contraseña y evita inyección SQL."""
    if not usuario or not password:
        return []

    password_hash = hashlib.sha256(password.strip().encode("utf-8")).hexdigest()

    try:
        with sqlite3.connect(DB_PATH) as conexion:
            cursor = conexion.cursor()
            query = "SELECT * FROM usuarios WHERE user = ? AND password_hash = ?"
            cursor.execute(query, (usuario, password_hash))
            return cursor.fetchall()
    except sqlite3.Error:
        return []