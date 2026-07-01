
import pytest
from backend.lexer import AnalizadorLexicoTrafico, _extraer_flags
from backend.parser import AnalizadorSintacticoTrafico
from backend.semantic import AnalizadorSemanticoTrafico
from backend.tokens import TipoToken

def test_rf02_analisis_lexico_regex_flags():
    """RF-02: Las expresiones regulares deben aislar perfectamente los lexemas TCP."""
    flags_sucias = "  SYN , PSH \n"
    resultado = _extraer_flags(flags_sucias)
    assert "SYN" in resultado
    assert "PSH" in resultado
    assert "ACK" not in resultado

def test_rf03_analisis_sintactico_ventanas(flujo_valido_syn):
    """RF-03: Estructura los flujos en ventanas de tiempo generando un AST válido."""
    lexer = AnalizadorLexicoTrafico()
    tokens = lexer.tokenizar(flujo_valido_syn)
    
    parser = AnalizadorSintacticoTrafico(ventana_segundos=10)
    estructura = parser.analizar(tokens)
    
    assert "arbol_sintactico" in estructura
    assert estructura["ventanas_analizadas"] == 1
    assert "raiz" in estructura["arbol_sintactico"]

def test_rf04_analisis_semantico_evita_falsos_positivos(flujo_valido_syn):
    """RF-04: El análisis semántico debe descartar ataques si no superan los PPS mínimos (Evita falsos positivos)."""
    lexer = AnalizadorLexicoTrafico()
    tokens = lexer.tokenizar(flujo_valido_syn)
    
    parser = AnalizadorSintacticoTrafico(ventana_segundos=10)
    estructura = parser.analizar(tokens)
    
    semantico = AnalizadorSemanticoTrafico()
    analisis = semantico.evaluar(estructura, flujo_valido_syn)
    
    assert analisis["ataque_detectado"] is False
    assert analisis["tipo_ataque"] == "SIN_ATAQUE"


def test_rf04_analisis_semantico_confirma_ataque_real(flujo_valido_syn):
    """RF-04: El sistema debe confirmar el ataque y calcular métricas si supera los umbrales lógicos."""
    flujo_critico = flujo_valido_syn.copy()
    flujo_critico[0]["packets"] = 1500 
    
    lexer = AnalizadorLexicoTrafico()
    tokens = lexer.tokenizar(flujo_critico)
    
    parser = AnalizadorSintacticoTrafico(ventana_segundos=10)
    estructura = parser.analizar(tokens)
    
    semantico = AnalizadorSemanticoTrafico()
    analisis = semantico.evaluar(estructura, flujo_critico)
    
    assert analisis["ataque_detectado"] is True
    assert analisis["tipo_ataque"] == "SYN_FLOOD"
    assert "pps_pico" in analisis["metricas"]
    assert analisis["metricas"]["pps_pico"] == 1500.0