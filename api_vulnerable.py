"""API local de laboratorio, endurecida contra command injection y XSS."""
import html
import shlex
import subprocess

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)


@app.get("/api/diagnostico")
def diagnostico():
    texto = request.args.get("texto", "")
    if len(texto) > 1000:
        return jsonify(error="El texto supera el límite permitido."), 400

    resultado = subprocess.run(
        f"printf '%s\n' {shlex.quote(texto)}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    return jsonify(
        entrada=texto,
        salida=resultado.stdout,
        error=resultado.stderr,
        codigo_salida=resultado.returncode,
    )


@app.get("/saludo")
def saludo():
    nombre = request.args.get("nombre", "visitante")
    nombre_seguro = html.escape(nombre, quote=True)
    return make_response(
        f"<!doctype html><html><body><h1>Hola, {nombre_seguro}</h1></body></html>",
        200,
        {"Content-Type": "text/html; charset=utf-8"},
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
