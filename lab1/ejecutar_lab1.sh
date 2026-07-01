#!/bin/bash
# =============================================================================
# ejecutar_lab1.sh
# -----------------------------------------------------------------------------
# Proyecto    : Examen Final - Seguridad Informatica - Unidad IV
# Laboratorio : 1 (script auxiliar)
# Autor       : fran franklin calizaya apaza
# Subido por  : fran
# -----------------------------------------------------------------------------
# Ejecuta en orden las tres tareas del Laboratorio 1:
#   1.1  analizar_ssh.py  -> reporte_ssh.json
#   1.2  analizar_web.py  -> reporte_web.json
#   1.3  visualizar.py    -> graficas/*.png
#
# USO
#   cd lab1
#   bash ejecutar_lab1.sh
#
# Se detiene ante el primer error (set -e) para no seguir con datos incompletos.
# =============================================================================
set -e

# Situarse siempre en la carpeta del script, se invoque desde donde se invoque.
cd "$(dirname "$0")"

echo "=============================================="
echo " Laboratorio 1 - Analisis forense de logs"
echo "=============================================="

echo
echo "[Tarea 1.1] Analisis de fuerza bruta SSH (auth.log)..."
python3 analizar_ssh.py

echo
echo "[Tarea 1.2] Analisis del log de acceso web (access.log)..."
python3 analizar_web.py

echo
echo "[Tarea 1.3] Generacion de graficas..."
python3 visualizar.py

echo
echo "Lab 1 completado. Revise reporte_ssh.json, reporte_web.json y graficas/."
