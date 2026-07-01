"""Fase 1: tokenización fila a fila del tráfico de red."""
import re
from backend.tokens import TipoToken
from backend.thresholds import UMBRALES

_PUERTOS_AMPLIFICADORES = set(UMBRALES["amplificacion"]["puertos_origen_amplificadores"])

# Regex maestro: cada flag TCP como grupo nombrado; recorrido con finditer + lastgroup
_REGEX_FLAGS_TCP = re.compile(
    r"(?P<SYN>\bSYN\b)|(?P<ACK>\bACK\b)|(?P<FIN>\bFIN\b)"
    r"|(?P<RST>\bRST\b)|(?P<PSH>\bPSH\b)|(?P<URG>\bURG\b)"
)

# Definición de reglas léxicas: token canónico → patrón regex → ejemplo de lexema
_REGEX_TEORICO = [
    {
        "token": TipoToken.FLOW_RECORD,
        "patron": r"^\S+,\S+,\S+,\d+,\d+,(TCP|UDP|ICMP),\d+,\d+,\d+,.*$",
        "ejemplo": "2026-01-01T00:00:00Z,1.1.1.1,2.2.2.2,1024,80,TCP,1,64,5,SYN",
    },
    {
        "token": TipoToken.SYN_SOLO,
        "patron": r"(?=.*\bSYN\b)(?!.*\bACK\b)",
        "ejemplo": "SYN",
    },
    {
        "token": TipoToken.PUERTO_AMPLIFICADOR,
        "patron": r"\b(53|123|389|161|1900|11211|19|17)\b",
        "ejemplo": "src_port=53 (UDP)",
    },
    {
        "token": TipoToken.ICMP_FLOOD_CANDIDATO,
        "patron": r"\bICMP\b",
        "ejemplo": "ICMP",
    },
    {
        "token": TipoToken.HTTP_HIGH_FREQ,
        "patron": r"\b(80|443)\b",
        "ejemplo": "dst_port=80",
    },
]


def _extraer_flags(tcp_flags_str):
    """Extrae el conjunto de lexemas (flags TCP) usando el regex maestro con grupos nombrados."""
    return {m.lastgroup for m in _REGEX_FLAGS_TCP.finditer(tcp_flags_str)}


class AnalizadorLexicoTrafico:
    def tokenizar(self, flujos):
        """Clasifica cada flujo en uno o más tipos de token. Retorna lista de dicts."""
        tokens = []
        conteo_http = {}  # (src_ip, segundo_truncado) -> count

        for f in flujos:
            segundo = f["timestamp"][:19]
            tipos = self._clasificar(f, conteo_http, segundo)
            for tipo in tipos:
                tokens.append({"tipo": tipo, "flujo": f})

        return tokens

    def _clasificar(self, f, conteo_http, segundo):
        tipos = [TipoToken.FLOW_RECORD]
        proto = f["protocol"]

        if proto == "TCP":
            flag_lexemas = _extraer_flags(f["tcp_flags"])
            if "SYN" in flag_lexemas and "ACK" not in flag_lexemas:
                tipos.append(TipoToken.SYN_SOLO)

        if f["src_port"] in _PUERTOS_AMPLIFICADORES and proto == "UDP":
            tipos.append(TipoToken.PUERTO_AMPLIFICADOR)

        if proto == "ICMP":
            tipos.append(TipoToken.ICMP_FLOOD_CANDIDATO)

        if proto == "TCP" and f["dst_port"] in (80, 443):
            clave = (f["src_ip"], segundo)
            conteo_http[clave] = conteo_http.get(clave, 0) + 1
            if conteo_http[clave] >= 10:
                tipos.append(TipoToken.HTTP_HIGH_FREQ)

        return tipos

    def resumen_tokens(self, tokens):
        """Cuenta tokens por tipo para el JSON de salida."""
        conteo = {
            "flow_records": 0,
            "syn_solo": 0,
            "puerto_amplificador_origen": 0,
            "icmp_flood_candidato": 0,
            "http_request_alta_frecuencia": 0,
        }
        for t in tokens:
            tipo = t["tipo"]
            if tipo == TipoToken.FLOW_RECORD:
                conteo["flow_records"] += 1
            elif tipo == TipoToken.SYN_SOLO:
                conteo["syn_solo"] += 1
            elif tipo == TipoToken.PUERTO_AMPLIFICADOR:
                conteo["puerto_amplificador_origen"] += 1
            elif tipo == TipoToken.ICMP_FLOOD_CANDIDATO:
                conteo["icmp_flood_candidato"] += 1
            elif tipo == TipoToken.HTTP_HIGH_FREQ:
                conteo["http_request_alta_frecuencia"] += 1
        return conteo

    def obtener_regex_teorico(self):
        """Retorna las reglas léxicas (token, patrón regex, ejemplo) para vista académica."""
        return [
            {"token": r["token"], "patron": r["patron"], "ejemplo": r["ejemplo"]}
            for r in _REGEX_TEORICO
        ]
