import sys
import os
import io
from flask import Flask, render_template, request, jsonify
from backend.ingestion import IngestorTrafico
from backend.lexer import AnalizadorLexicoTrafico
from backend.parser import AnalizadorSintacticoTrafico
from backend.semantic import AnalizadorSemanticoTrafico
from backend.output_gen import GeneradorMitigacionDDoS

app = Flask(__name__, template_folder="frontend/templates", static_folder="frontend/static")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analizar", methods=["POST"])
def analizar():
    # Aceptar multipart (archivo) o JSON crudo
    if request.content_type and "multipart" in request.content_type:
        archivo = request.files.get("archivo")
        if not archivo:
            return jsonify({"error": "No se recibió ningún archivo."}), 400
        nombre = archivo.filename.lower()
        formato = "json" if nombre.endswith(".json") else "csv"
        buffer = io.BytesIO(archivo.read())
    else:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Cuerpo de la petición inválido."}), 400
        if "filas" in data:
            import json
            buffer = io.BytesIO(json.dumps(data["filas"]).encode())
            formato = "json"
        else:
            return jsonify({"error": "Se esperaba un archivo multipart o JSON con clave 'filas'."}), 400

    try:
        ingestor = IngestorTrafico()
        flujos, reporte_ingesta = ingestor.cargar(buffer, formato)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    lexer = AnalizadorLexicoTrafico()
    tokens = lexer.tokenizar(flujos)
    resumen_tokens = lexer.resumen_tokens(tokens)
    regex_teorico = lexer.obtener_regex_teorico()

    parser = AnalizadorSintacticoTrafico(ventana_segundos=10)
    estructura = parser.analizar(tokens)

    semantico = AnalizadorSemanticoTrafico()
    analisis = semantico.evaluar(estructura, flujos)

    generador = GeneradorMitigacionDDoS()
    salida_mitigacion = generador.generar(analisis)

    return jsonify({
        "ingesta": reporte_ingesta,
        "tokens": resumen_tokens,
        "regex_teorico": regex_teorico,
        "estructura": estructura,
        "analisis_semantico": {
            "ataque_detectado": analisis["ataque_detectado"],
            "tipo_ataque": analisis["tipo_ataque"],
            "severidad": analisis["severidad"],
            "objetivo": analisis.get("objetivo"),
            "metricas": analisis.get("metricas", {}),
            "regla_aplicada": analisis.get("regla_aplicada", ""),
        },
        "fuentes_top": analisis.get("fuentes_top", []),
        "acciones_mitigacion": salida_mitigacion["acciones_mitigacion"],
        "reglas_firewall": salida_mitigacion["reglas_firewall"],
    })


@app.route("/notificar", methods=["POST"])
def notificar():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Cuerpo de la petición inválido."}), 400

    correo = data.get("correo", "").strip()
    if not correo:
        return jsonify({"status": "error", "message": "El campo correo es obligatorio."}), 400

    res = data.get("resultado", {})
    sem = res.get("analisis_semantico", {})
    tipo = sem.get("tipo_ataque", "DESCONOCIDO")
    severidad = sem.get("severidad", "-")
    ataque = sem.get("ataque_detectado", False)

    asunto = f"[Motor DDoS] {'⚠ Ataque detectado' if ataque else 'Sin amenazas'}: {tipo} — Severidad {severidad}"

    obj = sem.get("objetivo")
    objetivo_str = f"{obj['ip']}:{obj['puerto']} ({obj['servicio']})" if obj else "No identificado"

    metricas = sem.get("metricas", {})
    metricas_str = "\n".join(f"  {k}: {v}" for k, v in metricas.items()) or "  Sin métricas"

    acciones = res.get("acciones_mitigacion", [])
    acciones_str = "\n".join(f"  - {a}" for a in acciones) or "  Sin acciones"

    ingesta = res.get("ingesta", {})

    mensaje = (
        f"REPORTE AUTOMÁTICO DE ANÁLISIS DE TRÁFICO\n"
        f"{'=' * 45}\n\n"
        f"Ataque detectado : {'Sí' if ataque else 'No'}\n"
        f"Tipo de ataque   : {tipo}\n"
        f"Severidad        : {severidad}\n"
        f"Objetivo         : {objetivo_str}\n"
        f"Regla aplicada   : {sem.get('regla_aplicada', '-')}\n\n"
        f"INGESTA\n{'-' * 20}\n"
        f"  Filas totales  : {ingesta.get('filas_totales', '-')}\n"
        f"  Filas válidas  : {ingesta.get('filas_validas', '-')}\n\n"
        f"MÉTRICAS\n{'-' * 20}\n{metricas_str}\n\n"
        f"ACCIONES DE MITIGACIÓN\n{'-' * 20}\n{acciones_str}\n"
    )

    generador = GeneradorMitigacionDDoS()
    resultado = generador.enviar_notificacion_gmail(correo, asunto, mensaje)

    if resultado["status"] == "error" and "SMTP_USER" in resultado.get("message", ""):
        return jsonify(resultado), 503

    return jsonify(resultado)


if __name__ == "__main__":
    app.run()
