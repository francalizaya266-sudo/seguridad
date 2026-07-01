#!/usr/bin/env python3
"""
exportar_csv.py
=============================================================================
Proyecto    : Examen Final - Seguridad Informatica - Unidad IV
Laboratorio : 4 - Tarea 4 (Dashboard SOC / exportacion de alertas)
Autor       : fran franklin calizaya apaza
Subido por  : fran
Fecha       : junio 2026
=============================================================================

DESCRIPCION
    Convierte una exportacion de alertas de Wazuh/OpenSearch (formato JSON
    de respuesta de la API _search) en un archivo CSV plano y facil de
    revisar en una hoja de calculo.

ESTRUCTURA DE ENTRADA
    La API de OpenSearch/Elasticsearch devuelve los documentos dentro de
    data["hits"]["hits"], y cada documento guarda la alerta real en el
    campo "_source". Este script extrae todos los "_source" y los aplana
    (json_normalize) para que los campos anidados (p. ej. rule.level,
    data.srcip) se conviertan en columnas independientes.

USO
    # Usando las rutas por defecto:
    python3 exportar_csv.py

    # Indicando explicitamente el JSON de entrada y/o el CSV de salida:
    python3 exportar_csv.py alertas_muestra.json alertas_muestra.csv
"""

import json
import sys
from pathlib import Path

import pandas as pd

# El CSV se escribe SIEMPRE junto a este script (carpeta lab4/), sin importar
# desde donde se ejecute. Se evitan rutas absolutas fijas para que el proyecto
# sea portable entre maquinas.
DIR_SCRIPT = Path(__file__).resolve().parent

# Entrada por defecto: el volcado que genera la consulta a la API de Wazuh.
ENTRADA_DEFECTO = Path("/tmp/alertas_muestra.json")
SALIDA_DEFECTO = DIR_SCRIPT / "alertas_muestra.csv"


def exportar(ruta_entrada: Path, ruta_salida: Path) -> int:
    """Lee el JSON de alertas, aplana los documentos y los guarda como CSV.

    Devuelve el numero de registros exportados."""
    with ruta_entrada.open(encoding="utf-8") as f:
        data = json.load(f)

    # Cada elemento de hits["hits"] es un documento; la alerta vive en "_source".
    hits = [h["_source"] for h in data["hits"]["hits"]]

    # json_normalize convierte los objetos anidados en columnas planas.
    df = pd.json_normalize(hits)
    df.to_csv(ruta_salida, index=False)
    return len(df)


def main():
    # Argumentos opcionales: [1] JSON de entrada, [2] CSV de salida.
    ruta_entrada = Path(sys.argv[1]) if len(sys.argv) > 1 else ENTRADA_DEFECTO
    ruta_salida = Path(sys.argv[2]) if len(sys.argv) > 2 else SALIDA_DEFECTO

    if not ruta_entrada.exists():
        print(f"Error: no se encontro el archivo de entrada {ruta_entrada}")
        sys.exit(1)

    total = exportar(ruta_entrada, ruta_salida)
    print(f"{total} registros exportados a {ruta_salida}")


if __name__ == "__main__":
    main()
