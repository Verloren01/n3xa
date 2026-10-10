"""Project-scoped file access and safe Python syntax checks."""

import shlex
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT_SECONDS = 8
MAX_COMMAND_OUTPUT = 4000
_BLOCKED_DIRECTORIES = {".git", "venv", "__pycache__"}


def resolver_ruta(ruta: str) -> Path:
    """Resolve a path and ensure it remains within the project root."""
    if not isinstance(ruta, str) or not ruta.strip():
        raise ValueError("La ruta debe ser un texto no vacío.")

    solicitada = Path(ruta).expanduser()
    if not solicitada.is_absolute():
        solicitada = PROJECT_ROOT / solicitada

    ruta_final = solicitada.resolve()
    try:
        ruta_final.relative_to(PROJECT_ROOT)
    except ValueError as e:
        raise ValueError("La ruta solicitada está fuera del proyecto.") from e
    return ruta_final


def leer_archivo(ruta: str) -> str:
    """Read a file located within the project root."""
    try:
        ruta_final = resolver_ruta(ruta)
        if not ruta_final.is_file():
            return f"Error: No se encontró un archivo válido para {ruta!r}."
        return ruta_final.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as e:
        return f"Error al leer {ruta!r}: {e}"


def validar_destino_escritura(ruta: str, contenido: str) -> str | None:
    """Return a validation error if the requested file cannot be overwritten."""
    try:
        ruta_final = resolver_ruta(ruta)
        ruta_original = Path(ruta).expanduser()
        if not ruta_original.is_absolute():
            ruta_original = PROJECT_ROOT / ruta_original

        if ruta_original.is_symlink():
            return "Error: No se permite sobrescribir enlaces simbólicos."
        if not ruta_final.is_file():
            return f"Error: Solo se pueden sobrescribir archivos existentes: {ruta!r}."

        partes = ruta_final.relative_to(PROJECT_ROOT).parts
        if any(parte in _BLOCKED_DIRECTORIES for parte in partes):
            return "Error: No se permite escribir en directorios internos del entorno."
        if ruta_final.name == ".env" or ruta_final.name.startswith(".env."):
            return "Error: No se permite sobrescribir archivos de entorno."
        if not isinstance(contenido, str) or not contenido:
            return "Error: El contenido nuevo debe ser texto no vacío."
        return None
    except (OSError, ValueError) as e:
        return f"Error al escribir {ruta!r}: {e}"


def escribir_archivo(ruta: str, contenido: str) -> str:
    """Overwrite an existing project file after validating the destination."""
    error = validar_destino_escritura(ruta, contenido)
    if error:
        return error

    try:
        ruta_final = resolver_ruta(ruta)
        ruta_final.write_text(contenido, encoding="utf-8")
        return f"Éxito: {ruta_final.relative_to(PROJECT_ROOT)} fue guardado."
    except (OSError, ValueError) as e:
        return f"Error al escribir {ruta!r}: {e}"


def ejecutar_comando(comando: str) -> str:
    """Only allow bounded Python syntax checking of project files."""
    if not isinstance(comando, str) or not comando.strip() or len(comando) > 300:
        return "Error: El comando debe ser texto no vacío de hasta 300 caracteres."

    try:
        argumentos = shlex.split(comando)
    except ValueError as e:
        return f"Error: No se pudo interpretar el comando: {e}"

    if len(argumentos) != 4 or argumentos[:3] != ["python", "-m", "py_compile"]:
        return (
            "Error: Comando no permitido. Solo se admite "
            "`python -m py_compile <archivo.py>` dentro del proyecto."
        )

    ruta = Path(argumentos[3])
    ruta_solicitada = ruta if ruta.is_absolute() else PROJECT_ROOT / ruta
    try:
        archivo = resolver_ruta(str(ruta_solicitada))
    except ValueError as e:
        return f"Error: {e}"

    if ruta_solicitada.is_symlink():
        return "Error: No se permite comprobar enlaces simbólicos."
    if not archivo.is_file() or archivo.suffix != ".py":
        return "Error: El objetivo debe ser un archivo Python existente."
    if any(parte in _BLOCKED_DIRECTORIES for parte in archivo.relative_to(PROJECT_ROOT).parts):
        return "Error: No se permite ejecutar comandos sobre directorios internos."

    validador = (
        "import pathlib,sys; "
        "compile(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), "
        "sys.argv[1], 'exec')"
    )
    try:
        resultado = subprocess.run(
            [sys.executable, "-I", "-c", validador, str(archivo)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return f"Error: La comprobación superó el límite de {COMMAND_TIMEOUT_SECONDS} segundos."
    except OSError as e:
        return f"Error: No se pudo iniciar la comprobación: {e}"

    salida = (resultado.stdout + resultado.stderr).strip()
    if resultado.returncode:
        detalle = salida[:MAX_COMMAND_OUTPUT] or "El archivo no compila."
        return f"Error de sintaxis en {archivo.relative_to(PROJECT_ROOT)}:\n{detalle}"
    return f"OK: Sintaxis válida en {archivo.relative_to(PROJECT_ROOT)}."
