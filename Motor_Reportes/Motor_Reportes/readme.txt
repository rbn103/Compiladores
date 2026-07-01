Motor de Detección DDoS - USIL 2026
=====================================

FLUJO DEL COMPILADOR
--------------------
Fase 0 (Ingesta)  : Lee CSV/JSON, valida columnas y descarta filas inválidas.
Fase 1 (Léxico)   : Clasifica cada flow en tokens tipados (SYN_SOLO, ICMP_FLOOD_CANDIDATO, etc.).
Fase 2 (Sintáctico): Agrega en ventanas de 10 s, detecta candidatos a ataque y construye AST.
Fase 3 (Semántico): Confirma tipo de ataque, asigna severidad y calcula métricas pico.
Fase 4 (Salida)   : Genera acciones de mitigación específicas y reglas de firewall ejecutables.

FORMATO CSV DE ENTRADA
----------------------
Columnas obligatorias (orden libre):
  timestamp, src_ip, dst_ip, src_port, dst_port,
  protocol, packets, bytes, duration_ms, tcp_flags

  - timestamp : ISO8601  ej. 2026-06-18T14:23:01Z
  - protocol  : TCP | UDP | ICMP
  - tcp_flags : SYN | SYN,ACK | ACK | FIN,ACK | (vacío si no es TCP)

ATAQUES DETECTADOS
------------------
  SYN_FLOOD, AMPLIFICACION, HTTP_FLOOD, PING_FLOOD, VOLUMETRICO

ARCHIVOS DE MUESTRA
-------------------
  samples/trafico_normal.csv            - 200 filas, tráfico legítimo
  samples/trafico_syn_flood.csv         - 5 000 filas, SYN flood hacia 10.0.0.5:80
  samples/trafico_amplificacion_dns.csv - 2 000 filas, amplificación DNS

VARIABLES DE ENTORNO
--------------------
  SMTP_USER     : cuenta Gmail remitente (ej. alerta@empresa.com)
  SMTP_PASSWORD : contraseña de aplicación de Gmail (16 caracteres)
  Si no están definidas, /notificar devuelve HTTP 503.

CÓMO CORRER LOCALMENTE
-----------------------
  1. python -m venv .venv
  2. .venv\Scripts\activate          (Windows) / source .venv/bin/activate (Linux)
  3. pip install -r requirements.txt
  4. set SMTP_USER=tu@gmail.com      (opcional)
  5. set SMTP_PASSWORD=xxxx          (opcional)
  6. python app.py
  7. Abrir http://localhost:5000
