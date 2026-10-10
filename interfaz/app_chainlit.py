import chainlit as cl
import json
import os
import re
from langchain_ollama import ChatOllama

# ==========================================
# 1. CONFIGURACIÓN DEL CEREBRO
# ==========================================
llm = ChatOllama(model="qwen2.5-coder:7b", temperature=0.1)

# ==========================================
# 2. HERRAMIENTAS (MODO NATIVO)
# ==========================================
def leer_archivo(ruta: str) -> str:
    """Lee un archivo local en el disco del usuario."""
    try:
        nombre_archivo = os.path.basename(ruta)
        ruta_final = os.path.join(os.getcwd(), nombre_archivo)
        
        if not os.path.exists(ruta_final):
            return f"Error: El archivo {nombre_archivo} no se encontró en {os.getcwd()}."
            
        with open(ruta_final, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error crítico al leer {ruta_final}: {str(e)}"

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
        
        # Buscamos cualquier bloque de texto que parezca un JSON con nuestra herramienta
        match_json = re.search(r'\{[\s\S]*"herramienta"[\s\S]*\}', texto_llm)
        
        if match_json:
            try:
                accion = json.loads(match_json.group(0))
                
                if accion.get("herramienta") == "leer_archivo":
                    archivo_objetivo = accion.get("ruta")
                    msg.content = f"⚙️ **Acción detectada:** Extrayendo `{archivo_objetivo}` del disco..."
                    await msg.update()
                    
                    codigo_leido = leer_archivo(archivo_objetivo)
                    
                    # Le pasamos el código al LLM simulando que él usó la herramienta
                    historial.append(("assistant", match_json.group(0)))
                    historial.append(("user", f"CONTENIDO DEL ARCHIVO:\n```\n{codigo_leido}\n```\n\nRealiza la auditoría de seguridad ahora."))
                    
                    msg.content += "\n📂 **Archivo cargado.** Analizando vulnerabilidades..."
                    await msg.update()
                    
                    # Segunda llamada para la auditoría real
                    respuesta_final = await llm.ainvoke(historial)
                    texto_final = respuesta_final.content
                    
                    historial.append(("assistant", texto_final))
                    msg.content = texto_final
                    await msg.update()
                    return
            except json.JSONDecodeError:
                pass # Si el regex atrapó basura, seguimos adelante

        # Si no detectó intención de usar herramienta, responde normalmente
        historial.append(("assistant", texto_llm))
        msg.content = texto_llm
        await msg.update()

    except Exception as e:
        msg.content = f"⚠️ Error interno: {str(e)}"
        await msg.update()