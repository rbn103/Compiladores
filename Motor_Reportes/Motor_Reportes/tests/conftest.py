import pytest

@pytest.fixture
def flujo_valido_syn():
    """Retorna un flujo legítimo que contiene un ataque SYN para pruebas."""
    return [
        {
            "timestamp": "2026-06-29T09:30:00Z",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "src_port": 4000,
            "dst_port": 80,
            "protocol": "TCP",
            "packets": 150,
            "bytes": 9600,
            "duration_ms": 100,
            "tcp_flags": "SYN"
        }
    ]

@pytest.fixture
def columnas_obligatorias():
    return [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "packets", "bytes", "duration_ms", "tcp_flags"
    ]

