# Laboratorio 1 — Análisis forense de logs con Python

Análisis forense de registros del sistema para detectar actividad maliciosa a
partir de `auth.log` (SSH) y `access.log` (Apache), con visualización de los
hallazgos.

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `analizar_ssh.py` | Detecta fuerza bruta SSH sobre `auth.log`. Cuenta los `Failed password` por IP y alerta cuando una IP supera el umbral (50 intentos). Exporta `reporte_ssh.json`. |
| `analizar_web.py` | Analiza `access.log` (Combined Log Format) y busca escaneo de directorios, errores 4xx/5xx por IP e intentos de SQL Injection. Exporta `reporte_web.json`. |
| `visualizar.py` | Genera 3 gráficas en `graficas/` a partir de los reportes: Top 10 IPs SSH, línea de tiempo HTTP y mapa de calor hora/código de respuesta. |
| `auth.log`, `access.log` | Logs de entrada (datasets del curso). |
| `reporte_ssh.json`, `reporte_web.json` | Reportes generados por los scripts. |
| `graficas/` | Imágenes PNG generadas por `visualizar.py`. |
| `evidencias/` | Capturas de pantalla de la ejecución (SCR-1.1a, SCR-1.1b, SCR-1.2a, SCR-1.2b). |

## Ejecución

```bash
source ~/venv-examen/bin/activate
cd lab1
python3 analizar_ssh.py     # -> reporte_ssh.json
python3 analizar_web.py     # -> reporte_web.json
python3 visualizar.py       # -> graficas/*.png
```

## Resultados obtenidos

- **253** intentos SSH fallidos en total.
- **2** IPs por encima del umbral de fuerza bruta: `45.33.32.156` (120 intentos)
  y `193.32.162.55` (58 intentos).
- **24** intentos de SQL Injection detectados en el log web.

## Notas técnicas

- `analizar_web.py` decodifica la URL con `unquote()` antes de buscar patrones
  de SQLi, de modo que un payload ofuscado con URL-encoding (p. ej. `%27`) no
  evada la detección.
- El escaneo de directorios se detecta con una ventana deslizante de 60 s:
  más de 20 rutas distintas desde la misma IP en ese intervalo dispara la alerta.
- `visualizar.py` usa el backend `Agg` de matplotlib para poder generar las
  imágenes en un servidor headless (la VM del examen, sin entorno gráfico).
