
import pytest
from backend.output_gen import GeneradorMitigacionDDoS
from backend.tokens import TipoAtaque

def test_rf05_generacion_reglas_firewall():
    """RF-05 y RNF-02: Genera comandos DROP evaluando el segmento de red /24 del atacante de manera veloz."""
    generador = GeneradorMitigacionDDoS()
    
    resultado_semantico_simulado = {
        "tipo_ataque": TipoAtaque.SYN_FLOOD,
        "objetivo": {"ip": "10.0.0.1", "puerto": 80},
        "fuentes_top": [{"ip": "192.168.1.50", "paquetes": 5000}]
    }
    
    salida = generador.generar(resultado_semantico_simulado)
    
    assert len(salida["reglas_firewall"]) > 0
    assert salida["reglas_firewall"][0]["src"] == "192.168.1.0/24"
    assert salida["reglas_firewall"][0]["accion"] == "DROP"
