# Laboratorio 2 — Reglas de correlación en Wazuh

Reglas locales personalizadas para el SIEM Wazuh (v4.9.2) que detectan dos
escenarios de ataque mediante correlación de eventos.

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `local_rules_ssh.xml` | Regla `100001` (nivel 10): detecta fuerza bruta SSH correlacionando fallos de autenticación repetidos desde la misma IP. |
| `local_rules_exfil.xml` | Reglas `100012`/`100013`/`100014`: correlación en dos etapas que detecta posible exfiltración de datos (login fuera de horario + transferencia > 500 MB). |
| `simular_bruteforce.sh` | Simulador que inyecta eventos `Failed password` en el syslog con `logger` para probar la regla de fuerza bruta sin conexiones SSH reales. |
| `evidencias/` | Capturas de la ejecución (SCR-2.1, SCR-2.2, SCR-2.3). |

## Despliegue de las reglas

```bash
sudo cp local_rules_ssh.xml   /var/ossec/etc/rules/
sudo cp local_rules_exfil.xml /var/ossec/etc/rules/
sudo xmllint --noout /var/ossec/etc/rules/local_rules_ssh.xml   && echo OK
sudo xmllint --noout /var/ossec/etc/rules/local_rules_exfil.xml && echo OK
sudo systemctl restart wazuh-manager
```

## Prueba de la regla de fuerza bruta

```bash
sudo bash simular_bruteforce.sh 203.0.113.50 15
sudo grep "Ataque de fuerza bruta SSH" /var/ossec/logs/alerts/alerts.log | tail
```

Con la regla bien configurada debería aparecer: `Rule ID: 100001 | Level: 10 | brute_force`.

## Notas de configuración importantes

- Se añadió `/var/log/auth.log` como fuente de logs en `/var/ossec/etc/ossec.conf`
  (la instalación por defecto solo leía `journald`).
- La regla `100001` se apoya en `if_sid 5763` (regla nativa de brute force de
  Wazuh 4.9.2): en esta versión los fallos SSH escalan por las reglas 5760–5763.
- La regla de exfiltración `100013` usa `<if_sid>530</if_sid>` como **marcador de
  ejemplo**; debe reemplazarse por el `sid` real del decoder/regla que procesa
  los logs de tráfico saliente del firewall/proxy en cada entorno.
- La correlación final `100014` (nivel 14) modela el escenario real: alguien
  entra fuera de horario laboral y poco después saca un gran volumen de datos.
