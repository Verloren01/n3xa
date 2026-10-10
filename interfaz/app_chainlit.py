import chainlit as cl
import json
import os
import re
from langchain_ollama import ChatOllama

# ==========================================
# 1. CONFIGURACIÓN DEL CEREBRO
# ==========================================
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
llm = ChatOllama(model="qwen2.5-coder:7b", temperature=0.1)

# ==========================================
# 2. HERRAMIENTAS (MODO NATIVO)
# ==========================================
def _resolver_ruta(ruta: str) -> str:
    """Resuelve una ruta dentro del proyecto y evita escapes de directorio."""
    if not ruta or not isinstance(ruta, str):
        raise ValueError("La ruta debe ser un texto no vacío.")

    ruta_expandida = os.path.expanduser(ruta)
    if os.path.isabs(ruta_expandida):
        ruta_final = ruta_expandida
    else:
        ruta_final = os.path.join(PROJECT_ROOT, ruta_expandida)

    ruta_final = os.path.realpath(ruta_final)
    if os.path.commonpath([PROJECT_ROOT, ruta_final]) != PROJECT_ROOT:
        raise ValueError(f"La ruta solicitada está fuera del proyecto: {ruta}")

    return ruta_final


def leer_archivo(ruta: str) -> str:
    """Lee un archivo local dentro del directorio del proyecto."""
    try:
        ruta_final = _resolver_ruta(ruta)

        if not os.path.exists(ruta_final):
            return f"Error: El archivo {ruta} no se encontró en {PROJECT_ROOT}."

        if not os.path.isfile(ruta_final):
            return f"Error: La ruta {ruta} no es un archivo válido."

        with open(ruta_final, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Error crítico al leer {ruta}: {str(e)}"


def extraer_json_herramienta(texto: str):
    """Obtiene el primer bloque JSON con la clave 'herramienta' del texto."""
    for match in re.finditer(r"\{.*?\}", texto, re.DOTALL):
        bloque = match.group(0)
        if '"herramienta"' not in bloque:
            continue
        try:
            return json.loads(bloque)
        except json.JSONDecodeError:
            continue
    return None

# ==========================================
# 3. DIRECTRICES DEL SISTEMA
# ==========================================
# Directriz estricta para forzar el comportamiento de agente
INSTRUCCIONES = """Eres n3xa, un agente DevSecOps en Omarchy Linux.
REGLA SUPREMA: NUNCA digas que no tienes acceso a los archivos. Tienes una herramienta para leerlos.

Si el usuario te pide auditar, leer, o revisar un archivo, DEBES responder obligatoriamente con un bloque JSON con esta estructura exacta:
{"herramienta": "leer_archivo", "ruta": "nombre_del_archivo.py"}

No escribas código Python. No pidas disculpas. Responde SOLO con el JSON.
Cuando recibas el contenido del archivo en el siguiente mensaje, entonces redacta tu auditoría de seguridad completa."""

# ==========================================
# 4. MOTOR DEL AGENTE AUTÓNOMO (EXTRACTOR REGEX)
# ==========================================
@cl.on_chat_start
async def on_chat_start():
    await cl.Message(
        content="🔌 **Sistema n3xa actualizado.**\nMotor de extracción Regex activo. Qwen está bajo control estricto. ¿Qué archivo auditamos hoy?"
    ).send()
    cl.user_session.set("historial", [("system", INSTRUCCIONES)])

@cl.on_message
async def on_message(message: cl.Message):
    historial = cl.user_session.get("historial")
    historial.append(("user", message.content))

    msg = cl.Message(content="🧠 n3xa está pensando...")
    await msg.send()

    try:
        respuesta = await llm.ainvoke(historial)
        texto_llm = respuesta.content.strip()

        accion = extraer_json_herramienta(texto_llm)

        if accion:
            try:
                if accion.get("herramienta") == "leer_archivo":
                    archivo_objetivo = accion.get("ruta")
                    msg.content = f"⚙️ **Acción detectada:** Extrayendo `{archivo_objetivo}` del disco..."
                    await msg.update()

                    codigo_leido = leer_archivo(archivo_objetivo)

                    historial.append(("assistant", json.dumps(accion, ensure_ascii=False)))
                    historial.append(("user", f"CONTENIDO DEL ARCHIVO:\n```\n{codigo_leido}\n```\n\nRealiza la auditoría de seguridad ahora."))

                    msg.content += "\n📂 **Archivo cargado.** Analizando vulnerabilidades..."
                    await msg.update()

                    respuesta_final = await llm.ainvoke(historial)
                    texto_final = respuesta_final.content

                    historial.append(("assistant", texto_final))
                    msg.content = texto_final
                    await msg.update()
                    return
            except (TypeError, ValueError):
                pass

        historial.append(("assistant", texto_llm))
        msg.content = texto_llm
        await msg.update()

    except Exception as e:
        msg.content = f"⚠️ Error interno: {str(e)}"
        await msg.update()