# Laboratorio 3 — Detección de anomalías con Machine Learning

Modelo no supervisado (**Isolation Forest**) que detecta tráfico de red anómalo
sobre un dataset de 10.000 registros, con exportación del modelo para inferencia
en producción.

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `deteccion_anomalias.ipynb` | Notebook con todo el flujo: exploración, preprocesamiento, entrenamiento, evaluación y optimización del umbral (Tareas 3.1–3.4). |
| `predecir.py` | Script de inferencia: carga `modelo_anomalias.pkl` y clasifica un CSV nuevo como normal/anomalía sin reentrenar. |
| `network_traffic.csv` | Dataset de entrenamiento (10.000 registros, 30 días). La columna `label` solo se usa para validar. |
| `nuevo_trafico.csv` | Muestra de tráfico nuevo para probar `predecir.py`. |
| `modelo_anomalias.pkl` | Modelo serializado (modelo + `scaler` + lista de `features`). |
| `evidencias/` | Capturas de la ejecución (SCR-3.1 … SCR-3.4). |

## Ejecución

```bash
source ~/venv-examen/bin/activate
cd lab3
jupyter notebook --no-browser --port=8888 --ip=0.0.0.0   # ejecutar el notebook
python3 predecir.py nuevo_trafico.csv                     # inferencia
```

## Resultados obtenidos

| Métrica | Umbral por defecto (0) | Umbral óptimo (-0.0531) |
|---------|:---:|:---:|
| F1-Score | 0.802 | **0.876** |

- Se aplicó transformación logarítmica (`log1p`) a las variables de bytes para
  corregir su cola pesada; sin este paso el F1 baja de ~0.8 a ~0.6.
- Los 10 registros más anómalos corresponden todos a `label='anomaly'` real:
  `bytes_sent` de miles de millones con `duration_sec` corto, patrón típico de
  exfiltración de datos.

## Nota importante sobre `predecir.py`

El preprocesamiento (features derivadas + `log1p` + escalado) debe ser
**exactamente el mismo** que se usó al entrenar. Por eso `predecir.py` reutiliza
el `scaler` y la lista de `features` guardados dentro del `.pkl`: si los datos
llegaran en otra escala, las predicciones no serían válidas.
