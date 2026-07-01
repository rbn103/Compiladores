UMBRALES = {
    "volumetrico": {
        "fuentes_distintas_min": 500,
        "pps_min": 5000,
        "ventana_segundos": 10,
    },
    "syn_flood": {
        "ratio_syn_sin_ack_min": 0.85,
        "pps_min": 100,
    },
    "amplificacion": {
        "ratio_bytes_respuesta_request_min": 10.0,
        "puertos_origen_amplificadores": [53, 123, 389, 161, 1900, 11211, 19, 17],
    },
    "http_flood": {
        "requests_por_segundo_min": 1000,
        "fuentes_distintas_min": 100,
    },
    "ping_flood": {
        "pps_min": 500,
        "ratio_icmp_min": 0.7,
    },
}

SEVERIDADES = {
    "CRITICA": "Activar respuesta inmediata, posible saturación de enlace",
    "ALTA":    "Aplicar mitigación dentro de 5 minutos",
    "MEDIA":   "Monitoreo activo y mitigación preventiva",
    "BAJA":    "Registrar y observar tendencia",
}
