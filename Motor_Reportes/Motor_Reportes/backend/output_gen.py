"""Fase 4: generación de acciones de mitigación, reglas de firewall y notificación."""
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from backend.tokens import TipoAtaque


_ACCIONES = {
    TipoAtaque.SYN_FLOOD: [
        "Activar SYN cookies en el balanceador frontal",
        "Reducir timeout de conexiones half-open a 5 segundos",
        "Aplicar rate limit de 100 SYN/s por IP origen en firewall perimetral",
        "Anunciar blackhole /32 hacia el destino vía BGP al ISP upstream",
        "Considerar redirección a centro de scrubbing externo",
    ],
    TipoAtaque.AMPLIFICACION: [
        "Bloquear tráfico UDP entrante desde puertos 53, 123, 389, 161, 1900, 11211, 19, 17",
        "Activar BCP38 anti-spoofing en el router de borde",
        "Anunciar blackhole de tráfico amplificado hacia el ISP upstream",
        "Reducir TTL de respuestas DNS propias para limitar amplificación saliente",
        "Contactar con el CERT nacional para coordinación de bloqueo de reflectores",
    ],
    TipoAtaque.HTTP_FLOOD: [
        "Activar modo under-attack en el WAF perimetral",
        "Implementar CAPTCHA o JS challenge para peticiones HTTP nuevas",
        "Bloquear User-Agents y patrones de URI recurrentes identificados en los logs",
        "Aplicar rate limit de 50 req/s por IP en el balanceador de carga",
        "Activar caché agresivo de páginas estáticas para aliviar carga en backend",
    ],
    TipoAtaque.PING_FLOOD: [
        "Bloquear ICMP echo-request entrante en el router de borde (ACL de entrada)",
        "Aplicar rate limit de 100 pps para tráfico ICMP en el firewall",
        "Anunciar blackhole del destino vía BGP si el enlace está saturado",
        "Verificar que ICMP outbound no esté siendo utilizado como canal de exfiltración",
        "Revisar si el flood proviene de reflectores (Smurf) y bloquear broadcast amplification",
    ],
    TipoAtaque.VOLUMETRICO: [
        "Activar scrubbing center o servicio anti-DDoS del ISP de forma inmediata",
        "Anunciar blackhole /32 del destino atacado vía BGP community 666",
        "Aumentar capacidad de enlace de forma temporal contactando al ISP",
        "Aplicar ACL de bloqueo para los rangos /24 de las top-10 fuentes identificadas",
        "Activar QoS para priorizar tráfico legítimo sobre el volumen de ataque",
    ],
}


class GeneradorMitigacionDDoS:
    def generar(self, resultado_semantico):
        """Retorna acciones y reglas de firewall según el tipo de ataque."""
        tipo = resultado_semantico.get("tipo_ataque", TipoAtaque.SIN_ATAQUE)

        if tipo == TipoAtaque.SIN_ATAQUE:
            return {
                "acciones_mitigacion": ["No se detectó ataque. Continuar monitoreo rutinario."],
                "reglas_firewall": [],
            }

        acciones = _ACCIONES.get(tipo, ["Aplicar filtrado genérico de tráfico anómalo."])
        reglas = self._generar_reglas_firewall(tipo, resultado_semantico)
        return {"acciones_mitigacion": acciones, "reglas_firewall": reglas}

    def _generar_reglas_firewall(self, tipo, resultado):
        reglas = []
        objetivo = resultado.get("objetivo") or {}
        dst_ip = objetivo.get("ip", "0.0.0.0")
        dst_port = objetivo.get("puerto", 0)
        fuentes = resultado.get("fuentes_top", [])
        top_src = fuentes[0]["ip"] if fuentes else "0.0.0.0"
        # Derivar /24 del top origen
        partes = top_src.split(".")
        red_24 = ".".join(partes[:3]) + ".0/24" if len(partes) == 4 else top_src

        if tipo == TipoAtaque.SYN_FLOOD:
            reglas.append({
                "accion": "DROP", "src": red_24, "dst": dst_ip,
                "dst_port": dst_port, "protocol": "TCP", "flags": "SYN",
            })
            reglas.append({
                "accion": "RATE_LIMIT", "src": "0.0.0.0/0", "dst": dst_ip,
                "dst_port": dst_port, "protocol": "TCP", "flags": "SYN",
                "limite": "100/s",
            })

        elif tipo == TipoAtaque.AMPLIFICACION:
            for puerto_amp in [53, 123, 389, 161, 1900, 11211, 19, 17]:
                reglas.append({
                    "accion": "DROP", "src": "0.0.0.0/0", "dst": dst_ip,
                    "src_port": puerto_amp, "protocol": "UDP",
                })

        elif tipo == TipoAtaque.HTTP_FLOOD:
            reglas.append({
                "accion": "RATE_LIMIT", "src": "0.0.0.0/0", "dst": dst_ip,
                "dst_port": dst_port, "protocol": "TCP", "limite": "50 req/s por IP",
            })
            reglas.append({
                "accion": "DROP", "src": red_24, "dst": dst_ip,
                "dst_port": dst_port, "protocol": "TCP",
            })

        elif tipo == TipoAtaque.PING_FLOOD:
            reglas.append({
                "accion": "DROP", "src": "0.0.0.0/0", "dst": dst_ip,
                "protocol": "ICMP", "icmp_type": "echo-request",
            })

        elif tipo == TipoAtaque.VOLUMETRICO:
            for fuente in fuentes[:5]:
                partes_f = fuente["ip"].split(".")
                red = ".".join(partes_f[:3]) + ".0/24" if len(partes_f) == 4 else fuente["ip"]
                reglas.append({
                    "accion": "BLACKHOLE", "src": red, "dst": dst_ip, "protocol": "ANY",
                })

        return reglas

    def enviar_notificacion_gmail(self, correo_destino, asunto, mensaje_texto):
        """Envía notificación por Gmail SMTP. Requiere SMTP_USER y SMTP_PASSWORD en entorno."""
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")

        if not smtp_user or not smtp_password:
            return {
                "status": "error",
                "message": "Servicio de notificación no configurado: variables SMTP_USER y SMTP_PASSWORD ausentes.",
            }

        try:
            msg = MIMEMultipart()
            msg["From"] = Header(smtp_user, "utf-8")
            msg["To"] = Header(correo_destino, "utf-8")
            msg["Subject"] = Header(asunto, "utf-8")
            msg.attach(MIMEText(mensaje_texto, "plain", "utf-8"))

            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, correo_destino, msg.as_bytes())
            server.quit()

            return {"status": "success", "message": "Notificación enviada con éxito."}
        except Exception as e:
            return {"status": "error", "message": f"Error de envío: {str(e)}"}
