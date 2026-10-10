"""Thin Chainlit adapter for the UI-independent n3xa agent."""

import sys
from pathlib import Path

import chainlit as cl

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent import Agent, AgentResponse

agent = Agent()


async def _render_response(message: cl.Message, response: AgentResponse) -> None:
    message.content = response.text
    if response.findings:
        message.elements = [
            cl.CustomElement(
                name="VulnerabilityFindings",
                props={"findings": response.findings},
            )
        ]
    await message.update()


@cl.on_chat_start
async def on_chat_start() -> None:
    await cl.Message(
        content=(
            "🔌 **Sistema n3xa listo.** Puedes pedirme que lea o audite archivos "
            "del proyecto. Las escrituras requieren confirmación."
        )
    ).send()
    cl.user_session.set("historial", agent.new_history())


@cl.on_message
async def on_message(message: cl.Message) -> None:
    historial = cl.user_session.get("historial")
    if not isinstance(historial, list):
        historial = agent.new_history()
        cl.user_session.set("historial", historial)

    texto_usuario = message.content if isinstance(message.content, str) else ""
    if not texto_usuario.strip():
        await cl.Message(
            content=(
                "⚠️ No encontré texto en el mensaje. Reenvía la solicitud como texto; "
                "no necesito rutas temporales ni metadatos de adjuntos."
            )
        ).send()
        return

    respuesta = cl.Message(content="🧠 n3xa está pensando...")
    await respuesta.send()
    try:
        resultado = await agent.handle_message(texto_usuario, historial)
        if resultado.pending_action:
            ruta = resultado.pending_action["ruta"]
            confirmacion = await cl.AskActionMessage(
                content=f"{resultado.text}\n\n¿Autorizas la escritura?",
                actions=[
                    cl.Action(
                        name="aprobar_escritura",
                        payload={"decision": "aprobar"},
                        label=f"Autorizar {ruta}",
                    ),
                    cl.Action(
                        name="rechazar_escritura",
                        payload={"decision": "rechazar"},
                        label="Cancelar",
                    ),
                ],
            ).send()
            aprobado = (
                bool(confirmacion)
                and confirmacion.get("payload", {}).get("decision") == "aprobar"
            )
            resultado = await agent.complete_pending_action(
                resultado.pending_action,
                aprobado,
                historial,
            )
        await _render_response(respuesta, resultado)
    except FileNotFoundError:
        respuesta.content = (
            "⚠️ No se encontró un archivo temporal o recurso asociado al mensaje. "
            "Reenvía la solicitud como texto; el agente solo opera sobre archivos "
            "existentes dentro del proyecto."
        )
        await respuesta.update()
    except Exception as error:
        respuesta.content = f"⚠️ Error interno del agente: {error}"
        await respuesta.update()
