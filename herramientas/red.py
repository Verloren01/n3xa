"""Safe Nmap reconnaissance limited to private and loopback targets."""

import ipaddress
import subprocess

from .archivos import (
    MAX_OUTPUT_LENGTH,
    limitar_salida,
)

NMAP_TIMEOUT_SECONDS = 30


def escanear_red(objetivo: str) -> str:
    """Run a fast Nmap version scan against a private or loopback IP only."""
    if not isinstance(objetivo, str):
        return "Error de seguridad: el objetivo debe ser una IP válida o localhost."

    objetivo = objetivo.strip()
    if objetivo == "localhost":
        pass
    else:
        try:
            direccion = ipaddress.ip_address(objetivo)
        except ValueError:
            return (
                "Error de seguridad: solo se permiten IPs privadas, loopback "
                "o el objetivo exacto 'localhost'."
            )
        if not (direccion.is_private or direccion.is_loopback):
            return (
                "Error de seguridad: se rechazó el escaneo de una IP pública. "
                "Solo se permiten IPs privadas o loopback."
            )

    try:
        resultado = subprocess.run(
            ["nmap", "-sV", "-F", objetivo],
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return (
            "Error: No se encontró Nmap en el sistema. "
            "Solicita la instalación del paquete nmap en Omarchy."
        )
    except subprocess.TimeoutExpired:
        return f"Error: Nmap superó el límite de {NMAP_TIMEOUT_SECONDS} segundos."
    except OSError as error:
        return f"Error: No se pudo iniciar Nmap: {error}"

    salida = resultado.stdout.strip()
    if resultado.returncode and resultado.stderr.strip():
        detalle = resultado.stderr.strip()
        salida = f"{salida}\n{detalle}" if salida else detalle
    if not salida:
        salida = f"Nmap terminó con código {resultado.returncode} sin salida."

    if len(salida) <= MAX_OUTPUT_LENGTH:
        return salida
    return limitar_salida(salida)
