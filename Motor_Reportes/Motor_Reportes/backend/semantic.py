"""Fase 3: confirmación del tipo de ataque y métricas pico."""
from collections import Counter, defaultdict
from backend.tokens import TipoAtaque, TipoCandidato, Severidad
from backend.thresholds import UMBRALES


_CANDIDATO_A_ATAQUE = {
    TipoCandidato.SYN_FLOOD:    TipoAtaque.SYN_FLOOD,
    TipoCandidato.AMPLIFICACION: TipoAtaque.AMPLIFICACION,
    TipoCandidato.HTTP_FLOOD:   TipoAtaque.HTTP_FLOOD,
    TipoCandidato.PING_FLOOD:   TipoAtaque.PING_FLOOD,
    TipoCandidato.VOLUMETRICO:  TipoAtaque.VOLUMETRICO,
}

_SERVICIOS = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
              25: "SMTP", 21: "FTP", 3389: "RDP", 3306: "MySQL"}


class AnalizadorSemanticoTrafico:
    def evaluar(self, estructura, flujos):
        """Confirma ataque dominante, severidad y métricas pico."""
        candidatos = estructura.get("candidatos", [])

        if not candidatos:
            return {
                "ataque_detectado": False,
                "tipo_ataque": TipoAtaque.SIN_ATAQUE,
                "severidad": Severidad.SIN_ATAQUE,
                "objetivo": None,
                "metricas": {},
                "regla_aplicada": "Sin candidatos: tráfico dentro de umbrales normales.",
            }

        conteo = Counter(c["tipo"] for c in candidatos)
        tipo_candidato_dom = conteo.most_common(1)[0][0]
        tipo_ataque = _CANDIDATO_A_ATAQUE[tipo_candidato_dom]

        metricas = self._calcular_metricas(tipo_ataque, flujos)
        severidad = self._asignar_severidad(tipo_ataque, metricas)
        objetivo = self._identificar_objetivo(flujos)
        regla = self._regla_aplicada(tipo_ataque, metricas)

        fuentes_top = self._top_fuentes(flujos, n=10)

        return {
            "ataque_detectado": True,
            "tipo_ataque": tipo_ataque,
            "severidad": severidad,
            "objetivo": objetivo,
            "metricas": metricas,
            "regla_aplicada": regla,
            "fuentes_top": fuentes_top,
        }

    def _calcular_metricas(self, tipo_ataque, flujos):
        if not flujos:
            return {}

        total_paquetes = sum(f["packets"] for f in flujos)
        total_bytes = sum(f["bytes"] for f in flujos)
        timestamps = [f["timestamp"] for f in flujos]
        try:
            from datetime import datetime, timezone
            def ts(s):
                return datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=timezone.utc).timestamp()
            t0, t1 = ts(min(timestamps)), ts(max(timestamps))
            duracion = max(t1 - t0, 1.0)
        except Exception:
            duracion = 1.0

        pps = total_paquetes / duracion
        bps = total_bytes / duracion
        fuentes = len({f["src_ip"] for f in flujos})

        m = {
            "pps_pico": round(pps, 0),
            "bps_pico_humano": _humanizar_bps(bps),
            "fuentes_distintas": fuentes,
            "duracion_segundos": round(duracion, 1),
        }

        if tipo_ataque == TipoAtaque.SYN_FLOOD:
            syn_pkt = sum(f["packets"] for f in flujos
                          if f["protocol"] == "TCP"
                          and "SYN" in {fl.strip() for fl in f["tcp_flags"].split(",")}
                          and "ACK" not in {fl.strip() for fl in f["tcp_flags"].split(",")})
            m["ratio_syn_sin_ack"] = round(syn_pkt / total_paquetes, 2) if total_paquetes else 0.0

        elif tipo_ataque == TipoAtaque.AMPLIFICACION:
            amp_bytes = sum(f["bytes"] for f in flujos
                            if f["src_port"] in UMBRALES["amplificacion"]["puertos_origen_amplificadores"])
            req_bytes = total_bytes - amp_bytes
            m["ratio_amplificacion"] = round(amp_bytes / req_bytes, 1) if req_bytes > 0 else 0.0

        elif tipo_ataque == TipoAtaque.PING_FLOOD:
            icmp_pkt = sum(f["packets"] for f in flujos if f["protocol"] == "ICMP")
            m["ratio_icmp"] = round(icmp_pkt / total_paquetes, 2) if total_paquetes else 0.0

        return m

    def _asignar_severidad(self, tipo_ataque, metricas):
        pps = metricas.get("pps_pico", 0)
        fuentes = metricas.get("fuentes_distintas", 0)

        if tipo_ataque == TipoAtaque.SYN_FLOOD:
            if pps >= 1000:
                return Severidad.CRITICA
            if pps >= 100:
                return Severidad.ALTA
            if pps >= 20:
                return Severidad.MEDIA
            return Severidad.BAJA

        if tipo_ataque in (TipoAtaque.VOLUMETRICO, TipoAtaque.AMPLIFICACION):
            if pps >= 200000 or fuentes >= 10000:
                return Severidad.CRITICA
            if pps >= 50000:
                return Severidad.ALTA
            return Severidad.MEDIA

        if tipo_ataque == TipoAtaque.HTTP_FLOOD:
            rps = metricas.get("pps_pico", 0)
            if rps >= 5000:
                return Severidad.CRITICA
            if rps >= 1000:
                return Severidad.ALTA
            return Severidad.MEDIA

        if tipo_ataque == TipoAtaque.PING_FLOOD:
            if pps >= 20000:
                return Severidad.ALTA
            return Severidad.MEDIA

        return Severidad.BAJA

    def _identificar_objetivo(self, flujos):
        if not flujos:
            return None
        dst_counts = Counter(f["dst_ip"] for f in flujos)
        dst_ip = dst_counts.most_common(1)[0][0]
        puertos_dst = Counter(f["dst_port"] for f in flujos if f["dst_ip"] == dst_ip)
        puerto = puertos_dst.most_common(1)[0][0] if puertos_dst else 0
        return {"ip": dst_ip, "puerto": puerto, "servicio": _SERVICIOS.get(puerto, "Desconocido")}

    def _top_fuentes(self, flujos, n=10):
        conteo = defaultdict(int)
        total = 0
        for f in flujos:
            conteo[f["src_ip"]] += f["packets"]
            total += f["packets"]
        ordenado = sorted(conteo.items(), key=lambda x: x[1], reverse=True)[:n]
        return [
            {"ip": ip, "paquetes": pkt, "porcentaje": round(100 * pkt / total, 2) if total else 0}
            for ip, pkt in ordenado
        ]

    def _regla_aplicada(self, tipo_ataque, metricas):
        reglas = {
            TipoAtaque.SYN_FLOOD: (
                f"Regla 2: SYN sin ACK > {UMBRALES['syn_flood']['ratio_syn_sin_ack_min']*100:.0f}% "
                f"con > {UMBRALES['syn_flood']['pps_min']:,} pps sostenido"
            ),
            TipoAtaque.AMPLIFICACION: (
                "Regla 3: Tráfico UDP desde puertos amplificadores conocidos "
                f"(53, 123, 389, 161, 1900, 11211, 19, 17) con ratio bytes > "
                f"{UMBRALES['amplificacion']['ratio_bytes_respuesta_request_min']}x"
            ),
            TipoAtaque.HTTP_FLOOD: (
                f"Regla 4: HTTP/HTTPS > {UMBRALES['http_flood']['requests_por_segundo_min']} req/s "
                f"desde > {UMBRALES['http_flood']['fuentes_distintas_min']} fuentes distintas"
            ),
            TipoAtaque.PING_FLOOD: (
                f"Regla 5: ICMP > {UMBRALES['ping_flood']['ratio_icmp_min']*100:.0f}% del tráfico "
                f"con > {UMBRALES['ping_flood']['pps_min']:,} pps"
            ),
            TipoAtaque.VOLUMETRICO: (
                f"Regla 1: > {UMBRALES['volumetrico']['fuentes_distintas_min']:,} fuentes únicas "
                f"+ > {UMBRALES['volumetrico']['pps_min']:,} pps hacia un único destino"
            ),
        }
        return reglas.get(tipo_ataque, "Regla genérica de tráfico anómalo.")


def _humanizar_bps(bps):
    if bps >= 1e9:
        return f"{bps/1e9:.1f} Gbps"
    if bps >= 1e6:
        return f"{bps/1e6:.1f} Mbps"
    if bps >= 1e3:
        return f"{bps/1e3:.1f} Kbps"
    return f"{bps:.0f} bps"
