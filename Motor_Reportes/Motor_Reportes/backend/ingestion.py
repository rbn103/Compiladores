"""Fase 0: lectura y validación estructural del archivo de tráfico."""
import io
import ipaddress
import json
import pandas as pd
from backend.tokens import COLUMNAS_OBLIGATORIAS, PROTOCOLOS_VALIDOS


class IngestorTrafico:
    def cargar(self, path_o_buffer, formato="csv"):
        """Lee CSV o JSON; retorna (lista_dicts, reporte_ingesta). Falla rápido si faltan columnas."""
        if formato == "csv":
            df = pd.read_csv(path_o_buffer, dtype=str)
        else:
            if isinstance(path_o_buffer, (str, bytes)):
                datos = json.loads(path_o_buffer)
            else:
                datos = json.load(path_o_buffer)
            df = pd.DataFrame(datos if isinstance(datos, list) else [datos], dtype=str)

        faltantes = [c for c in COLUMNAS_OBLIGATORIAS if c not in df.columns]
        if faltantes:
            raise ValueError(f"Columnas obligatorias faltantes: {faltantes}")

        filas_validas = []
        motivos = {"ip_invalida": 0, "puerto_fuera_rango": 0, "protocolo_desconocido": 0, "otros": 0}

        for _, fila in df.iterrows():
            motivo = self._validar_fila(fila)
            if motivo is None:
                filas_validas.append(self._convertir(fila))
            else:
                motivos[motivo] = motivos.get(motivo, 0) + 1

        descartadas = len(df) - len(filas_validas)
        reporte = {
            "filas_totales": len(df),
            "filas_validas": len(filas_validas),
            "filas_descartadas": descartadas,
            "motivos_descarte": {k: v for k, v in motivos.items() if v > 0},
        }
        return filas_validas, reporte

    def _validar_fila(self, fila):
        for campo in ("src_ip", "dst_ip"):
            try:
                ipaddress.IPv4Address(str(fila[campo]).strip())
            except Exception:
                return "ip_invalida"

        for campo in ("src_port", "dst_port"):
            try:
                p = int(fila[campo])
                if not (0 <= p <= 65535):
                    raise ValueError
            except Exception:
                return "puerto_fuera_rango"

        proto = str(fila["protocol"]).strip().upper()
        if proto not in PROTOCOLOS_VALIDOS:
            return "protocolo_desconocido"

        return None

    def _convertir(self, fila):
        return {
            "timestamp":   str(fila["timestamp"]).strip(),
            "src_ip":      str(fila["src_ip"]).strip(),
            "dst_ip":      str(fila["dst_ip"]).strip(),
            "src_port":    int(fila["src_port"]),
            "dst_port":    int(fila["dst_port"]),
            "protocol":    str(fila["protocol"]).strip().upper(),
            "packets":     int(fila["packets"]),
            "bytes":       int(fila["bytes"]),
            "duration_ms": int(fila["duration_ms"]),
            "tcp_flags":   str(fila.get("tcp_flags", "")).strip().upper(),
        }
