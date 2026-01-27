# Dockerfile para Suricata IDS
FROM jasonish/suricata:latest

# Copiar configuración personalizada
COPY suricata.yaml /etc/suricata/suricata.yaml

# Directorio para logs
VOLUME /var/log/suricata

# Comando por defecto
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
