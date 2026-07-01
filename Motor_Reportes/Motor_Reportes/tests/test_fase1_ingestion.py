
import pytest
import pandas as pd
import io
from backend.ingestion import IngestorTrafico

def test_rf01_fast_fail_columnas_faltantes():
    """RF-01: El sistema debe lanzar ValueError inmediatamente si faltan columnas obligatorias."""
    ingestor = IngestorTrafico()
    
    csv_incompleto = "timestamp,src_ip,dst_ip,src_port,dst_port,packets,duration_ms,tcp_flags\n2026-06-29T09:30:00Z,1.1.1.1,2.2.2.2,80,80,10,10,SYN"
    buffer = io.BytesIO(csv_incompleto.encode())
    
    with pytest.raises(ValueError) as excinfo:
        ingestor.cargar(buffer, formato="csv")
    
    assert "Columnas obligatorias faltantes" in str(excinfo.value)

def test_rf01_filtrado_datos_invalidos(flujo_valido_syn):
    """RF-01: Valida el descarte correcto de IPs inválidas o puertos fuera de rango."""
    ingestor = IngestorTrafico()
    
    flujo_invalido = flujo_valido_syn.copy()
    flujo_invalido[0]["src_ip"] = "999.999.999.999" 
    
    df = pd.DataFrame(flujo_invalido)
    motivo = ingestor._validar_fila(df.iloc[0])
    
    assert motivo == "ip_invalida"

