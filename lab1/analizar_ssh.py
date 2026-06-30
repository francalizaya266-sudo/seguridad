#!/usr/bin/env python3
"""
analizar_ssh.py
=============================================================================
Proyecto    : Examen Final - Seguridad Informatica - Unidad IV
Laboratorio : 1 - Tarea 1.1 (Analisis forense de auth.log con Python)
Autor       : fran franklin calizaya apaza
Subido por  : fran
Fecha       : junio 2026
=============================================================================

DESCRIPCION
    Analiza el registro de autenticacion del sistema (auth.log) para
    detectar ataques de fuerza bruta contra el servicio SSH.

FLUJO DEL PROGRAMA
    1. Lee el archivo lab1/auth.log linea por linea.
    2. Identifica los intentos de autenticacion SSH fallidos mediante la
       expresion regular PATRON_FALLO ("Failed password ... from <IP>").
    3. Cuenta cuantos fallos provienen de cada direccion IP de origen.
    4. Construye un ranking Top 10 de las IPs mas agresivas.
    5. Emite una alerta en consola para toda IP que supere el umbral de
       fuerza bruta (UMBRAL_ALERTA = 50 intentos).
    6. Exporta el resultado estructurado a reporte_ssh.json.

PARAMETROS CONFIGURABLES
    LOG_PATH      : ruta del log de entrada (por defecto auth.log).
    REPORT_PATH   : ruta del reporte JSON de salida.
    UMBRAL_ALERTA : numero de intentos a partir del cual se considera
                    ataque de fuerza bruta.

USO
    python3 analizar_ssh.py
"""

import re
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_PATH = Path("auth.log")
REPORT_PATH = Path("reporte_ssh.json")
UMBRAL_ALERTA = 50

# Coincide con lineas tipo:
#   Mar 15 02:14:23 server sshd[12345]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2
#   Mar 15 02:14:23 server sshd[12345]: Failed password for root from 203.0.113.45 port 51234 ssh2
PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def leer_log(path: Path) -> list[str]:
    """Devuelve todas las lineas del log. Aborta con error claro si falta."""
    if not path.exists():
        raise FileNotFoundError(
            f"No se encontro {path}. Copie auth.log a la carpeta lab1/ antes de ejecutar."
        )
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def contar_intentos_fallidos(lineas: list[str]) -> Counter:
    """Recorre las lineas y acumula, por IP de origen, cuantos 'Failed
    password' produjo. Las lineas que no encajan con el patron se ignoran."""
    contador = Counter()
    for linea in lineas:
        match = PATRON_FALLO.search(linea)
        if match:
            contador[match.group("ip")] += 1
    return contador


def generar_alertas(contador: Counter) -> list[dict]:
    """Marca como sospechosa (alerta=True) toda IP por encima del umbral y
    la imprime en consola. Devuelve la lista completa ordenada por frecuencia
    para incluirla luego en el reporte JSON."""
    ips_sospechosas = []
    for ip, intentos in contador.most_common():
        alerta = intentos > UMBRAL_ALERTA
        if alerta:
            print(f"[ALERTA] IP: {ip} - {intentos} intentos fallidos - Posible ataque de fuerza bruta")
        ips_sospechosas.append({"ip": ip, "intentos": intentos, "alerta": alerta})
    return ips_sospechosas


def main():
    lineas = leer_log(LOG_PATH)
    contador = contar_intentos_fallidos(lineas)
    total_fallidos = sum(contador.values())

    print(f"Total de lineas analizadas: {len(lineas)}")
    print(f"Total de intentos fallidos detectados: {total_fallidos}")
    print(f"IPs distintas con intentos fallidos: {len(contador)}\n")

    print("=== Top 10 IPs con mas intentos fallidos ===")
    for posicion, (ip, intentos) in enumerate(contador.most_common(10), start=1):
        print(f"{posicion:>2}. {ip:<15} -> {intentos} intentos")
    print()

    print("=== Verificacion de umbral de fuerza bruta (>50 intentos) ===")
    ips_sospechosas = generar_alertas(contador)

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total_fallidos,
        "ips_sospechosas": sorted(
            ips_sospechosas, key=lambda x: x["intentos"], reverse=True
        )[:10],
    }

    with REPORT_PATH.open("w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\nReporte exportado a {REPORT_PATH.resolve()}")


if __name__ == "__main__":
    main()
