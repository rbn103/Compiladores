import os
import time
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By

def test_automatizacion_interfaz_carga_csv():
    """Prueba E2E: Automatiza el navegador para cargar un archivo y verificar la respuesta visual."""
    
    # 1. Inicializar el navegador Chrome de forma automatizada
    opciones = webdriver.ChromeOptions()
    driver = webdriver.Chrome(options=opciones)
    
    # Crear un archivo CSV temporal de prueba en  disco
    ruta_csv_prueba = os.path.abspath("trafico_selenium_test.csv")
    csv_contenido = (
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,duration_ms,tcp_flags\n"
        "2026-06-29T09:30:00Z,192.168.1.50,10.0.0.1,4000,80,TCP,1500,9600,100,SYN"
    )
    with open(ruta_csv_prueba, "w") as f:
        f.write(csv_contenido)

    try:
        # 2. Navegar a la interfaz 
        driver.get("http://127.0.0.1:5000/")
        driver.implicitly_wait(5) # Espera hasta 5 segundos a que carguen los elementos
        
        # 3. Localizar el input de tipo archivo y cargar el CSV
        boton_seleccionar_archivo = driver.find_element(By.CSS_SELECTOR, 'input[type="file"]')
        boton_seleccionar_archivo.send_keys(ruta_csv_prueba)
        
        # 4. Localizar y hacer clic en el botón de Analizar
        boton_analizar = driver.find_element(By.XPATH, "//button[contains(text(), 'Analizar') or contains(@id, 'analizar')]")
        boton_analizar.click()
        
        # 5. Esperar a que el backend procese e inserte los resultados en el DOM
        time.sleep(3) 
        
        # 6. Asertar que la pantalla muestra el veredicto del ataque
        contenido_pantalla = driver.page_source
        
        # Verificaciones en caliente en la interfaz gráfica
        assert "SYN_FLOOD" in contenido_pantalla or "DROP" in contenido_pantalla
        print("\n¡Prueba de Selenium exitosa! La interfaz procesó y mostró las reglas de mitigación.")

    finally:
        # Limpieza: Cerrar el navegador y borrar el archivo temporal
        driver.quit()
        if os.path.exists(ruta_csv_prueba):
            os.remove(ruta_csv_prueba)