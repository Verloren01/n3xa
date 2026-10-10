"""Semgrep SAST scanning constrained to the project root."""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .archivos import PROJECT_ROOT, resolver_ruta

SEMGREP_EXECUTABLE = Path.home() / ".local/share/venvs/n3xa-semgrep/bin/semgrep"
SEMGREP_TIMEOUT_SECONDS = 60
MAX_COMMAND_OUTPUT = 4000
MAX_SEMGREP_FINDINGS = 20
MAX_SEMGREP_OUTPUT = 12000
_BLOCKED_DIRECTORIES = {".git", "venv", "__pycache__"}


def _es_ruta_temporal_chainlit(ruta: str) -> bool:
    try:
        partes = Path(ruta).expanduser().parts
    except (TypeError, ValueError):
        return False

    return any(parte.lower() == ".files" for parte in partes) or (
        any(parte.lower() == "files" for parte in partes)
        and any(re.fullmatch(r"[0-9a-fA-F-]{32,}", parte) for parte in partes)
    )


def ejecutar_semgrep(ruta: str = ".") -> str:
    """Scan a project path and return a bounded JSON summary."""
    if not isinstance(ruta, str) or not ruta.strip():
        ruta = "."

    nota_ruta = None
    if _es_ruta_temporal_chainlit(ruta):
        ruta = "."
        nota_ruta = (
            "La ruta recibida era un archivo temporal de Chainlit, no una ruta fuente "
            "del proyecto; se escaneó la raíz del proyecto."
        )

    try:
        ruta_final = resolver_ruta(ruta)
    except (OSError, ValueError) as e:
        return f"Error: Ruta de escaneo no permitida: {e}"

    ruta_original = Path(ruta).expanduser()
    if not ruta_original.is_absolute():
        ruta_original = PROJECT_ROOT / ruta_original
    if ruta_original.is_symlink():
        return "Error: No se permite escanear un enlace simbólico."
    if not ruta_final.exists():
        return f"Error: No existe la ruta de escaneo {ruta!r}."
    if not (ruta_final.is_file() or ruta_final.is_dir()):
        return f"Error: La ruta de escaneo {ruta!r} no es un archivo o directorio."
    if any(parte in _BLOCKED_DIRECTORIES for parte in ruta_final.relative_to(PROJECT_ROOT).parts):
        return "Error: No se permite escanear directorios internos del entorno."

    executable = str(SEMGREP_EXECUTABLE) if SEMGREP_EXECUTABLE.is_file() else shutil.which("semgrep")
    if executable is None:
        return (
            "Error: Semgrep no está instalado o no se encuentra en PATH. "
            "Instala requirements-sast.txt en el entorno SAST aislado para habilitar el escaneo."
        )

    try:
        resultado = subprocess.run(
            [executable, "scan", "--config", "auto", str(ruta_final), "--json"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return (
            "Error: No se encontró el ejecutable de Semgrep. "
            "Instala requirements-sast.txt en el entorno SAST aislado."
        )
    except subprocess.TimeoutExpired:
        return f"Error: Semgrep superó el límite de {SEMGREP_TIMEOUT_SECONDS} segundos."
    except OSError as e:
        return f"Error: No se pudo iniciar Semgrep: {e}"

    if not resultado.stdout.strip():
        detalle = resultado.stderr.strip()[:MAX_COMMAND_OUTPUT]
        return (
            f"Error: Semgrep terminó con código {resultado.returncode} "
            f"sin generar JSON. {detalle}"
        )

    try:
        informe: Any = json.loads(resultado.stdout)
    except json.JSONDecodeError as e:
        detalle = (resultado.stderr.strip() or resultado.stdout.strip())[:MAX_COMMAND_OUTPUT]
        return f"Error: Semgrep devolvió JSON inválido ({e}). {detalle}"

    if not isinstance(informe, dict):
        return "Error: Semgrep devolvió un JSON con una estructura inesperada."
    resultados = informe.get("results")
    if not isinstance(resultados, list):
        return "Error: La respuesta JSON de Semgrep no contiene una lista de hallazgos."

    hallazgos = []
    for item in resultados[:MAX_SEMGREP_FINDINGS]:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra")
        if not isinstance(extra, dict):
            extra = {}
        ubicacion = item.get("start")
        if not isinstance(ubicacion, dict):
            ubicacion = {}

        ruta_hallazgo = item.get("path", "ruta desconocida")
        try:
            ruta_hallazgo = str(
                Path(ruta_hallazgo).resolve().relative_to(PROJECT_ROOT)
            )
        except (OSError, ValueError):
            ruta_hallazgo = str(ruta_hallazgo)

        metadata = extra.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        metadata_resumida = {}
        for clave in ("cwe", "confidence", "category", "owasp"):
            valor = metadata.get(clave)
            if isinstance(valor, list):
                metadata_resumida[clave] = [
                    str(elemento)[:120] for elemento in valor[:5]
                ]
            elif valor is not None:
                metadata_resumida[clave] = str(valor)[:200]

        hallazgos.append(
            {
                "rule_id": str(item.get("check_id", "regla desconocida")),
                "severity": str(extra.get("severity", "UNKNOWN")),
                "path": ruta_hallazgo,
                "line": ubicacion.get("line"),
                "message": str(extra.get("message", ""))[:350],
                "metadata": metadata_resumida,
            }
        )

    datos_rutas = informe.get("paths")
    if not isinstance(datos_rutas, dict):
        datos_rutas = {}
    rutas_escaneadas = datos_rutas.get("scanned", [])
    if not isinstance(rutas_escaneadas, list):
        rutas_escaneadas = []
    errores = informe.get("errors", [])
    if not isinstance(errores, list):
        errores = []
    errores_resumidos = []
    for error in errores[:5]:
        if isinstance(error, dict):
            detalle = error.get("message", json.dumps(error, ensure_ascii=False, default=str))
        else:
            detalle = str(error)
        errores_resumidos.append(str(detalle)[:400])

    resumen: dict[str, Any] = {
        "ruta_escaneada": str(ruta_final.relative_to(PROJECT_ROOT)) or ".",
        "hallazgos": hallazgos,
        "total_hallazgos": len(resultados),
        "hallazgos_omitidos_por_limite": max(0, len(resultados) - len(hallazgos)),
        "cantidad_rutas_escaneadas": len(rutas_escaneadas),
        "errores_semgrep": errores_resumidos,
        "codigo_salida": resultado.returncode,
    }
    if nota_ruta:
        resumen["nota"] = nota_ruta

    salida = json.dumps(resumen, ensure_ascii=False, default=str)
    while len(salida) > MAX_SEMGREP_OUTPUT and resumen["hallazgos"]:
        resumen["hallazgos"].pop()
        resumen["hallazgos_omitidos_por_limite"] += 1
        salida = json.dumps(resumen, ensure_ascii=False, default=str)
    if len(salida) > MAX_SEMGREP_OUTPUT:
        resumen["errores_semgrep"] = []
        resumen["nota"] = "Se omitieron detalles para respetar el límite de salida."
        salida = json.dumps(resumen, ensure_ascii=False, default=str)
    return salida
