"""
monitor_red.py - Monitor de logs de Suricata
Este módulo monitorea los eventos de seguridad detectados por Suricata.
"""

import json
import os
import asyncio
import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional

from config import Config
from database import db

logger = logging.getLogger(__name__)


class MonitorRed:
    """Clase para monitorear los logs de Suricata."""
    
    def __init__(self, logs_path: str = None):
        if logs_path is None:
            logs_path = Config.SURICATA_LOGS_PATH

        self.logs_path = logs_path
        self.eve_log_path = os.path.join(logs_path, Config.SURICATA_EVE_JSON)
        self.last_position = 0
        self.alert_count = 0
        self.event_types = {
            "alert": 0,
            "flow": 0,
            "dns": 0,
            "tls": 0,
            "http": 0
        }
        self.alert_callback: Optional[Callable] = None
    
    async def iniciar(self):
        """Inicia el monitoreo de logs de Suricata."""
        try:
            logger.info("Iniciando monitor de red...")
            
            # Verificar que existe el directorio de logs
            if not os.path.exists(self.logs_path):
                logger.warning(f"Directorio de logs no existe: {self.logs_path}")
                logger.info("Creando directorio de logs...")
                os.makedirs(self.logs_path, exist_ok=True)
            
            # Verificar archivo eve.json
            if not os.path.exists(self.eve_log_path):
                logger.warning(f"Archivo eve.json no existe: {self.eve_log_path}")
                logger.info("Esperando que Suricata cree el archivo...")
                await self._wait_for_log_file()
            
            # Obtener posición inicial (ir al final del archivo)
            if os.path.exists(self.eve_log_path):
                with open(self.eve_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(0, 2)  # Ir al final
                    self.last_position = f.tell()
                    logger.info(f"Posición inicial: {self.last_position}")
            
            logger.info("Monitor de red iniciado correctamente")
            logger.info(f"Monitoreando: {self.eve_log_path}")
            
            # Procesar eventos existentes
            await self._process_new_events()
            
            # Bucle de monitoreo continuo
            while True:
                await asyncio.sleep(5)  # Verificar cada 5 segundos
                await self._process_new_events()
                
        except Exception as e:
            logger.error(f"Error en monitor de red: {e}")
            raise
    
    async def _wait_for_log_file(self, timeout: int = 60):
        """Espera a que el archivo de log sea creado."""
        elapsed = 0
        while not os.path.exists(self.eve_log_path) and elapsed < timeout:
            await asyncio.sleep(1)
            elapsed += 1
        
        if not os.path.exists(self.eve_log_path):
            logger.error(f"Timeout esperando archivo eve.json")
    
    async def _process_new_events(self):
        """Procesa nuevos eventos en el archivo eve.json."""
        try:
            if not os.path.exists(self.eve_log_path):
                return

            # Detectar rotación de log: si el archivo es más pequeño que
            # la última posición leída, Suricata ha creado un nuevo archivo
            current_size = os.path.getsize(self.eve_log_path)
            if current_size < self.last_position:
                logger.info("Rotación de eve.json detectada, reiniciando posición")
                self.last_position = 0

            # Leer archivo desde la última posición
            with open(self.eve_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
            
            # Procesar cada línea (cada línea es un JSON)
            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    await self._process_event(event)
                except json.JSONDecodeError as e:
                    logger.warning(f"Error al parsear JSON: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error procesando eventos: {e}")
    
    async def _process_event(self, event: Dict):
        """Procesa un evento individual de Suricata."""
        try:
            event_type = event.get('event_type', 'unknown')
            
            # Incrementar contador
            if event_type in self.event_types:
                self.event_types[event_type] += 1
            
            # Procesar según tipo de evento
            if event_type == 'alert':
                await self._process_alert(event)
            elif event_type == 'flow':
                await self._process_flow(event)
            elif event_type == 'dns':
                await self._process_dns(event)
            elif event_type == 'tls':
                await self._process_tls(event)
            elif event_type == 'http':
                await self._process_http(event)
            
        except Exception as e:
            logger.error(f"Error procesando evento: {e}")
    
    async def _process_alert(self, event: Dict):
        """Procesa una alerta de seguridad."""
        try:
            alert = event.get('alert', {})
            
            # Extraer información relevante
            alerta_data = {
                "timestamp": event.get('timestamp', datetime.utcnow().isoformat()),
                "event_type": "alert",
                "severity": alert.get('severity', 0),
                "signature": alert.get('signature', 'Unknown'),
                "signature_id": alert.get('signature_id', 0),
                "category": alert.get('category', 'Unknown'),
                "source_ip": event.get('src_ip', 'Unknown'),
                "dest_ip": event.get('dest_ip', 'Unknown'),
                "source_port": event.get('src_port', 0),
                "dest_port": event.get('dest_port', 0),
                "protocol": event.get('proto', 'Unknown'),
                "raw_event": event
            }
            
            # Guardar en MongoDB
            await db.save_alert(alerta_data)
            
            self.alert_count += 1
            
            # Log de la alerta
            severity_emoji = ["ℹ️", "⚠️", "🚨", "🔥"][min(alert.get('severity', 1) - 1, 3)]
            logger.info(
                f"{severity_emoji} ALERTA [{alert.get('category')}]: "
                f"{alert.get('signature')} | "
                f"{event.get('src_ip')} → {event.get('dest_ip')}"
            )
            
            # Notificar por Telegram si es una alerta crítica (severity 1)
            if alert.get('severity') == 1 and self.alert_callback:
                await self.alert_callback(alerta_data)

        except Exception as e:
            logger.error(f"Error procesando alerta: {e}")
    
    async def _process_flow(self, event: Dict):
        """Procesa un evento de flujo de red."""
        # Por ahora solo lo registramos, podemos hacer análisis más complejo después
        logger.debug(f"Flow: {event.get('src_ip')} → {event.get('dest_ip')}")
    
    async def _process_dns(self, event: Dict):
        """Procesa un evento DNS."""
        dns = event.get('dns', {})
        query = dns.get('rrname', 'Unknown')
        
        # Detectar consultas DNS sospechosas
        suspicious_domains = [
            'telegram.org', 'telegram.me', 't.me'  # Dominios de Telegram
        ]
        
        if any(domain in query.lower() for domain in suspicious_domains):
            logger.info(f"DNS Query a Telegram: {query}")
    
    async def _process_tls(self, event: Dict):
        """Procesa un evento TLS."""
        tls = event.get('tls', {})
        sni = tls.get('sni', 'Unknown')
        
        # Registrar conexiones TLS a Telegram
        if 'telegram' in sni.lower():
            logger.info(f"TLS Connection a Telegram: {sni}")
    
    async def _process_http(self, event: Dict):
        """Procesa un evento HTTP."""
        http = event.get('http', {})
        hostname = http.get('hostname', 'Unknown')
        url = http.get('url', 'Unknown')
        
        logger.debug(f"HTTP: {hostname}{url}")
    
    def obtener_ultimas_alertas(self, cantidad: int = 10) -> List[Dict]:
        """
        Obtiene las últimas alertas registradas.
        
        Esta función es síncrona para compatibilidad.
        Para operaciones async, usar db.get_recent_alerts() directamente.
        """
        # Esta función puede ser mejorada para leer directamente del archivo
        # Por ahora retornamos una lista vacía y se debería usar db.get_recent_alerts()
        return []
    
    def obtener_estadisticas(self) -> Dict:
        """Obtiene estadísticas del monitor."""
        return {
            "alerts_count": self.alert_count,
            "event_types": self.event_types.copy(),
        }

    def detener(self):
        """Detiene el monitor."""
        logger.info("Monitor de red detenido")


# Instancia global
monitor_red = MonitorRed()


if __name__ == "__main__":
    # Test del monitor
    async def test():
        await db.connect()
        await monitor_red.iniciar()
    
    asyncio.run(test())

