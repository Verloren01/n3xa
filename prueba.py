import sqlite3

def login(usuario, password):
    # Contraseña quemada en el código (Mala práctica)
    secret_key = "super_admin_123"
    
    conexion = sqlite3.connect("database.db")
    cursor = conexion.cursor()
    
    # Vulnerabilidad crítica de OWASP: Inyección SQL (CWE-89)
    query = f"SELECT * FROM usuarios WHERE user = '{usuario}' AND password = '{password}'"
    cursor.execute(query)
    
    return cursor.fetchall()