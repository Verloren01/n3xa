"""Headless REST API adapter for the UI-independent n3xa agent."""

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent import Agent

app = FastAPI(
    title="n3xa API",
    description="API local para auditorías y diagnósticos con el agente n3xa.",
    version="1.0.0",
)
agent = Agent()


class AuditRequest(BaseModel):
    mensaje: str = Field(min_length=1, max_length=10_000)


class AuditResponse(BaseModel):
    respuesta: str
    acciones: list[dict[str, Any]]
    hallazgos: list[dict[str, str]]
    requiere_aprobacion: bool
    accion_pendiente: dict[str, str] | None = None


@app.post("/api/v1/auditar", response_model=AuditResponse)
async def auditar(request: AuditRequest) -> AuditResponse:
    """Process one message with a fresh history and return a plain JSON result."""
    history = agent.new_history()
    result = await agent.handle_message(request.mensaje, history)
    return AuditResponse(
        respuesta=result.text,
        acciones=result.actions,
        hallazgos=result.findings,
        requiere_aprobacion=result.pending_action is not None,
        accion_pendiente=(
            {
                "tipo": result.pending_action["kind"],
                "ruta": result.pending_action["ruta"],
            }
            if result.pending_action
            else None
        ),
    )
