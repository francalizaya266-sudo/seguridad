# Registro de cambios

Historial del desarrollo del examen final, organizado por laboratorio.
El formato sigue de forma laxa [Keep a Changelog](https://keepachangelog.com/es-ES/).

## Documentación

- README propio para cada laboratorio (`lab1`–`lab4`).
- `.gitattributes` para normalizar los finales de línea (LF en los `.sh`).
- Corrección de la autoría y limpieza del notebook del Lab 3.
- README principal detallado: arquitectura, entorno, estructura y reproducción.

## Laboratorio 4 — Dashboard SOC

- Script `exportar_csv.py` para volcar las alertas de Wazuh a CSV.
- Dashboard "SOC - Monitor de Seguridad" con 4 visualizaciones y monitor de
  alerta `soc-nivel-critico`.

## Laboratorio 3 — Detección de anomalías (ML)

- Notebook `deteccion_anomalias.ipynb` con Isolation Forest (Tareas 3.1–3.3).
- Transformación `log1p` de las variables de bytes (F1 de ~0.6 a ~0.8).
- Optimización del umbral de decisión: F1 de 0.802 → 0.876.
- Modelo serializado (`modelo_anomalias.pkl`) y script de inferencia
  `predecir.py` (Tarea 3.4).

## Laboratorio 2 — Reglas de correlación en Wazuh

- Regla de fuerza bruta SSH `100001` (Tarea 2.1).
- Regla compuesta de exfiltración de datos `100012`/`100013`/`100014` (Tarea 2.2).
- Simulador `simular_bruteforce.sh` para probar las reglas.

## Laboratorio 1 — Análisis forense de logs

- `analizar_ssh.py`: detección de fuerza bruta SSH sobre `auth.log` (Tarea 1.1).
- `analizar_web.py`: escaneo de directorios y SQL Injection sobre `access.log`
  (Tarea 1.2).
- `visualizar.py`: 3 gráficas de los hallazgos con matplotlib/seaborn (Tarea 1.3).

## Inicial

- Estructura del repositorio (`.gitignore`, `README`, `requirements.txt`).
- Carpetas de evidencias y gráficas de cada laboratorio.
