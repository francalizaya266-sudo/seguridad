#!/usr/bin/env python3
"""
analizar_web.py
=============================================================================
Proyecto    : Examen Final - Seguridad Informatica - Unidad IV
Laboratorio : 1 - Tarea 1.2 (Analisis del log de acceso web Apache)
Autor       : fran franklin calizaya apaza
Subido por  : fran
Fecha       : junio 2026
=============================================================================

DESCRIPCION
    Procesa el log de acceso de un servidor Apache (access.log) en formato
    Combined Log Format y busca tres indicadores de actividad maliciosa.

TECNICAS DE DETECCION IMPLEMENTADAS
    1. Escaneo de directorios : mas de 20 rutas distintas solicitadas por
       la misma IP dentro de una ventana deslizante de 60 segundos.
    2. Errores por IP         : agrupacion de codigos de respuesta 4xx/5xx
       por direccion de origen (util para detectar sondeo/fuzzing).
    3. SQL Injection          : busqueda de patrones tipicos (UNION, SELECT,
       comillas, OR 1=1, comentario '--') dentro de la URL decodificada.

SALIDA
    Imprime un resumen por consola y exporta el detalle completo a
    reporte_web.json.

USO
    python3 analizar_web.py
"""

import re
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

LOG_PATH = Path("access.log")
REPORT_PATH = Path("reporte_web.json")

VENTANA_ESCANEO_SEG = 60
UMBRAL_RUTAS_ESCANEO = 20

PATRONES_SQLI = ["UNION", "SELECT", "--", "OR 1=1", "'"]

# Coincide con el Combined Log Format estandar de Apache. La URL se captura
# de forma no-codiciosa hasta el literal " HTTP/x.x" (en vez de \S+) porque
# algunos payloads de prueba (ej. SQL Injection) llegan con espacios sin
# codificar dentro de la URL (ej. "GET /api?id=1 OR 1=1 HTTP/1.1"), y un
# patron basado en \S+ los descartaria por completo.
PATRON_CLF = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<url>.+?) HTTP/\d\.\d" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

FORMATO_FECHA_APACHE = "%d/%b/%Y:%H:%M:%S %z"


def parsear_log(path: Path) -> list[dict]:
    """Convierte cada linea valida del access.log en un diccionario con ip,
    metodo, url, status, size y timestamp ya parseado. Descarta lineas que
    no cumplen el formato o con fecha invalida."""
    if not path.exists():
        raise FileNotFoundError(
            f"No se encontro {path}. Copie access.log a la carpeta lab1/ antes de ejecutar."
        )
    registros = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            match = PATRON_CLF.search(linea)
            if not match:
                continue
            datos = match.groupdict()
            try:
                datos["timestamp"] = datetime.strptime(
                    datos["fecha"], FORMATO_FECHA_APACHE
                )
            except ValueError:
                continue
            registros.append(datos)
    return registros


def detectar_escaneo_directorios(registros: list[dict]) -> list[dict]:
    """Mas de 20 peticiones a rutas distintas en menos de 60s desde la misma IP."""
    por_ip = defaultdict(list)
    for r in registros:
        por_ip[r["ip"]].append(r)

    hallazgos = []
    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda x: x["timestamp"])
        inicio = 0
        for fin in range(len(eventos)):
            while (eventos[fin]["timestamp"] - eventos[inicio]["timestamp"]).total_seconds() > VENTANA_ESCANEO_SEG:
                inicio += 1
            ventana = eventos[inicio:fin + 1]
            rutas_distintas = {e["url"] for e in ventana}
            if len(rutas_distintas) > UMBRAL_RUTAS_ESCANEO:
                hallazgos.append({
                    "ip": ip,
                    "rutas_distintas": len(rutas_distintas),
                    "inicio": ventana[0]["timestamp"].isoformat(),
                    "fin": ventana[-1]["timestamp"].isoformat(),
                })
                break  # con un hallazgo por IP es suficiente para el reporte
    return hallazgos


def agrupar_codigos_error(registros: list[dict]) -> dict:
    """Cuenta, por IP, cuantas respuestas de error (codigo >= 400) genero.
    Estructura devuelta: {ip: {"404": 12, "500": 3, ...}}."""
    por_ip = defaultdict(lambda: defaultdict(int))
    for r in registros:
        codigo = int(r["status"])
        if codigo >= 400:
            por_ip[r["ip"]][str(codigo)] += 1
    return {ip: dict(codigos) for ip, codigos in por_ip.items()}


def detectar_sqli(registros: list[dict]) -> list[dict]:
    """Busca patrones de inyeccion SQL en la URL. Antes de comparar se
    aplica unquote() para deshacer el URL-encoding (ej. %27 -> comilla), de
    modo que un payload ofuscado no evada la deteccion."""
    hallazgos = []
    for r in registros:
        url_decodificada = unquote(r["url"]).upper()
        patrones_encontrados = [p for p in PATRONES_SQLI if p.upper() in url_decodificada]
        if patrones_encontrados:
            hallazgos.append({
                "ip": r["ip"],
                "url": r["url"],
                "patrones": patrones_encontrados,
                "timestamp": r["timestamp"].isoformat(),
            })
    return hallazgos


def main():
    registros = parsear_log(LOG_PATH)
    print(f"Total de lineas parseadas correctamente: {len(registros)}")

    print("\n=== Deteccion de escaneo de directorios ===")
    escaneos = detectar_escaneo_directorios(registros)
    if escaneos:
        for h in escaneos:
            print(f"[ALERTA] Escaneo detectado desde {h['ip']}: {h['rutas_distintas']} rutas distintas "
                  f"entre {h['inicio']} y {h['fin']}")
    else:
        print("No se detectaron patrones de escaneo de directorios.")

    print("\n=== Codigos de respuesta 4xx/5xx agrupados por IP ===")
    errores_por_ip = agrupar_codigos_error(registros)
    for ip, codigos in sorted(errores_por_ip.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]:
        print(f"{ip}: {codigos}")

    print("\n=== Deteccion de posibles intentos de SQL Injection ===")
    sqli = detectar_sqli(registros)
    if sqli:
        for h in sqli[:20]:
            print(f"[ALERTA] Posible SQLi desde {h['ip']}: {h['url']} -> patrones: {h['patrones']}")
        if len(sqli) > 20:
            print(f"... y {len(sqli) - 20} coincidencias adicionales (ver reporte_web.json)")
    else:
        print("No se detectaron patrones de SQL Injection.")

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones_analizadas": len(registros),
        "escaneo_directorios": escaneos,
        "codigos_error_por_ip": errores_por_ip,
        "intentos_sql_injection": sqli,
    }

    with REPORT_PATH.open("w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\nReporte exportado a {REPORT_PATH.resolve()}")


if __name__ == "__main__":
    main()
