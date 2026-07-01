# Laboratorio 4 — Dashboard de monitoreo SOC

Panel de monitoreo de seguridad construido sobre **Wazuh Dashboard** (OpenSearch
Dashboards) más una utilidad para exportar las alertas a CSV.

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `exportar_csv.py` | Convierte una exportación de alertas de la API de Wazuh/OpenSearch (JSON `_search`) en un CSV plano, aplanando los campos anidados (`rule.level`, `data.srcip`, …) con `json_normalize`. |
| `alertas_muestra.csv` | Muestra de alertas ya exportadas a CSV. |
| `evidencias/` | Capturas del dashboard y las visualizaciones (SCR-4.1 … SCR-4.4). |

## Exportar alertas a CSV

```bash
# Rutas por defecto (entrada /tmp/alertas_muestra.json):
python3 exportar_csv.py

# Indicando entrada y salida explícitas:
python3 exportar_csv.py alertas_muestra.json alertas_muestra.csv
```

## Dashboard "SOC - Monitor de Seguridad"

Accesible en `https://127.0.0.1:8443` (reenvío de puertos de VirtualBox).

- **Index pattern:** `wazuh-alerts-*`
- **4 visualizaciones:**
  1. Barras por severidad (`rule.level`).
  2. Tabla Top 10 IPs (`data.srcip`).
  3. Línea de alertas por hora (`@timestamp`).
  4. Pie chart por tipo de regla (`rule.groups`).
- **Monitor de alerta `soc-nivel-critico`:** se activa cuando el conteo de
  eventos con `rule.level >= 10` supera 5 en una ventana de 5 minutos.

## Nota técnica

`exportar_csv.py` escribe el CSV siempre junto al script (carpeta `lab4/`),
sin importar desde dónde se ejecute, para que el proyecto sea portable entre
máquinas (evita rutas absolutas fijas).
