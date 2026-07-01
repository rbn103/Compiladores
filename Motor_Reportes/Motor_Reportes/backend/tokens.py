# Fuente única de verdad para tipos de token y ataque
class TipoToken:
    FLOW_RECORD = "FLOW_RECORD"
    SYN_SOLO = "SYN_SOLO"
    PUERTO_AMPLIFICADOR = "PUERTO_AMPLIFICADOR"
    ICMP_FLOOD_CANDIDATO = "ICMP_FLOOD_CANDIDATO"
    HTTP_HIGH_FREQ = "HTTP_HIGH_FREQ"


class TipoAtaque:
    SYN_FLOOD = "SYN_FLOOD"
    AMPLIFICACION = "AMPLIFICACION"
    HTTP_FLOOD = "HTTP_FLOOD"
    PING_FLOOD = "PING_FLOOD"
    VOLUMETRICO = "VOLUMETRICO"
    SIN_ATAQUE = "SIN_ATAQUE"


class TipoCandidato:
    SYN_FLOOD = "CANDIDATO_SYN_FLOOD"
    AMPLIFICACION = "CANDIDATO_AMPLIFICACION"
    HTTP_FLOOD = "CANDIDATO_HTTP_FLOOD"
    PING_FLOOD = "CANDIDATO_PING_FLOOD"
    VOLUMETRICO = "CANDIDATO_VOLUMETRICO"


class Severidad:
    CRITICA = "CRITICA"
    ALTA = "ALTA"
    MEDIA = "MEDIA"
    BAJA = "BAJA"
    SIN_ATAQUE = "SIN_ATAQUE"


COLUMNAS_OBLIGATORIAS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packets", "bytes", "duration_ms", "tcp_flags"
]

PROTOCOLOS_VALIDOS = {"TCP", "UDP", "ICMP"}
