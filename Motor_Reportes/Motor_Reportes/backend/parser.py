"""Fase 2: agrupación temporal y detección de candidatos a ataque."""
from collections import defaultdict
from datetime import datetime, timezone
from backend.tokens import TipoToken, TipoCandidato
from backend.thresholds import UMBRALES


def _ts_epoch(ts_str):
    ts_str = ts_str.rstrip("Z")
    try:
        return datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return 0.0


class AnalizadorSintacticoTrafico:
    def __init__(self, ventana_segundos=10):
        self.ventana_segundos = ventana_segundos

    def analizar(self, tokens):
        """Construye candidatos y AST por ventana temporal. Retorna dict de estructura."""
        ventanas = self._agrupar_en_ventanas(tokens)
        candidatos = []
        nodos_arbol = []

        for ts_inicio, flujos_ventana in sorted(ventanas.items()):
            ts_label = datetime.fromtimestamp(ts_inicio, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            stats = self._estadisticas_ventana(flujos_ventana)
            candidatos_ventana = self._aplicar_reglas(ts_label, stats)
            candidatos.extend(candidatos_ventana)

            nodo = {
                "etiqueta": f"Ventana_{ts_label}",
                "hijos": [
                    f"dst_ip_dominante: {stats['dst_ip_dominante']}",
                    f"fuentes: {stats['fuentes_distintas']}",
                    f"pps: {stats['pps']:.0f}",
                    f"bps: {stats['bps']:.0f}",
                    f"ratio_syn: {stats['ratio_syn']:.2f}",
                ] + [f"candidato: {c['tipo']}" for c in candidatos_ventana],
            }
            nodos_arbol.append(nodo)

        return {
            "ventanas_analizadas": len(ventanas),
            "candidatos": candidatos,
            "arbol_sintactico": {
                "raiz": "Sesion_de_Trafico",
                "nodos": nodos_arbol,
            },
        }

    def _agrupar_en_ventanas(self, tokens):
        ventanas = defaultdict(list)
        for t in tokens:
            if t["tipo"] != TipoToken.FLOW_RECORD:
                continue
            epoch = _ts_epoch(t["flujo"]["timestamp"])
            bucket = int(epoch // self.ventana_segundos) * self.ventana_segundos
            ventanas[bucket].append(t["flujo"])
        return ventanas

    def _estadisticas_ventana(self, flujos):
        dst_counts = defaultdict(lambda: {"packets": 0, "bytes": 0, "src_ips": set(),
                                          "syn": 0, "ack": 0, "icmp": 0, "udp_amp": 0,
                                          "http": 0, "total": 0})
        puertos_amp = set(UMBRALES["amplificacion"]["puertos_origen_amplificadores"])

        for f in flujos:
            d = dst_counts[f["dst_ip"]]
            d["packets"] += f["packets"]
            d["bytes"] += f["bytes"]
            d["src_ips"].add(f["src_ip"])
            d["total"] += 1
            flags = {fl.strip() for fl in f["tcp_flags"].split(",")}
            if f["protocol"] == "TCP":
                if "SYN" in flags and "ACK" not in flags:
                    d["syn"] += f["packets"]
                if "ACK" in flags:
                    d["ack"] += f["packets"]
            if f["protocol"] == "ICMP":
                d["icmp"] += f["packets"]
            if f["protocol"] == "UDP" and f["src_port"] in puertos_amp:
                d["udp_amp"] += f["bytes"]
            if f["dst_port"] in (80, 443):
                d["http"] += 1

        if not dst_counts:
            return {"dst_ip_dominante": "N/A", "fuentes_distintas": 0, "pps": 0.0,
                    "bps": 0.0, "ratio_syn": 0.0, "ratio_icmp": 0.0,
                    "udp_amp_bytes": 0, "total_bytes": 0, "total_packets": 0,
                    "http_rps": 0.0, "http_fuentes": 0, "stats_por_dst": {}}

        dst_dom = max(dst_counts, key=lambda k: dst_counts[k]["packets"])
        d = dst_counts[dst_dom]
        total_pkt = d["packets"]
        ratio_syn = d["syn"] / total_pkt if total_pkt else 0.0
        ratio_icmp = d["icmp"] / total_pkt if total_pkt else 0.0
        pps = total_pkt / self.ventana_segundos
        bps = d["bytes"] / self.ventana_segundos

        return {
            "dst_ip_dominante": dst_dom,
            "fuentes_distintas": len(d["src_ips"]),
            "pps": pps,
            "bps": bps,
            "ratio_syn": ratio_syn,
            "ratio_icmp": ratio_icmp,
            "udp_amp_bytes": d["udp_amp"],
            "total_bytes": d["bytes"],
            "total_packets": total_pkt,
            "http_rps": d["http"] / self.ventana_segundos,
            "http_fuentes": len(d["src_ips"]) if d["http"] > 0 else 0,
            "stats_por_dst": {dst_dom: d},
        }

    def _aplicar_reglas(self, ts_label, s):
        candidatos = []
        u_vol = UMBRALES["volumetrico"]
        u_syn = UMBRALES["syn_flood"]
        u_amp = UMBRALES["amplificacion"]
        u_http = UMBRALES["http_flood"]
        u_ping = UMBRALES["ping_flood"]

        if s["fuentes_distintas"] >= u_vol["fuentes_distintas_min"] and s["pps"] >= u_vol["pps_min"]:
            candidatos.append({"ventana": ts_label, "tipo": TipoCandidato.VOLUMETRICO,
                                "evidencia": {"fuentes": s["fuentes_distintas"], "pps": s["pps"]}})

        if s["ratio_syn"] >= u_syn["ratio_syn_sin_ack_min"] and s["pps"] >= u_syn["pps_min"]:
            candidatos.append({"ventana": ts_label, "tipo": TipoCandidato.SYN_FLOOD,
                                "evidencia": {"ratio_syn": s["ratio_syn"], "pps": s["pps"]}})

        req_bytes = s["total_bytes"] - s["udp_amp_bytes"]
        if s["udp_amp_bytes"] > 0:
            ratio_amp = (s["udp_amp_bytes"] / req_bytes) if req_bytes > 0 else float("inf")
            if ratio_amp >= u_amp["ratio_bytes_respuesta_request_min"]:
                candidatos.append({"ventana": ts_label, "tipo": TipoCandidato.AMPLIFICACION,
                                    "evidencia": {"udp_amp_bytes": s["udp_amp_bytes"],
                                                  "ratio_amp": ratio_amp if ratio_amp != float("inf") else -1}})

        if s["http_rps"] >= u_http["requests_por_segundo_min"] and s.get("http_fuentes", 0) >= u_http["fuentes_distintas_min"]:
            candidatos.append({"ventana": ts_label, "tipo": TipoCandidato.HTTP_FLOOD,
                                "evidencia": {"http_rps": s["http_rps"]}})

        if s["ratio_icmp"] >= u_ping["ratio_icmp_min"] and s["pps"] >= u_ping["pps_min"]:
            candidatos.append({"ventana": ts_label, "tipo": TipoCandidato.PING_FLOOD,
                                "evidencia": {"ratio_icmp": s["ratio_icmp"], "pps": s["pps"]}})

        return candidatos
