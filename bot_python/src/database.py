"""
database.py - Módulo de gestión de base de datos MongoDB
Maneja todas las operaciones de persistencia de datos.
"""

import asyncio
from datetime import datetime
from typing import List, Dict, Optional, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
import logging

from config import Config

logger = logging.getLogger(__name__)


class Database:
    """Clase para gestionar la conexión y operaciones con MongoDB."""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self.messages: Optional[AsyncIOMotorCollection] = None
        self.alerts: Optional[AsyncIOMotorCollection] = None
        self.statistics: Optional[AsyncIOMotorCollection] = None
        self.threat_patterns: Optional[AsyncIOMotorCollection] = None
        self._connected = False
    
    async def connect(self):
        """Establece conexión con MongoDB."""
        try:
            logger.info(f"🔌 Conectando a MongoDB: {Config.MONGO_URI}")
            self.client = AsyncIOMotorClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
            
            # Verificar conexión
            await self.client.admin.command('ping')
            
            # Seleccionar base de datos
            self.db = self.client[Config.MONGO_DB_NAME]
            
            # Obtener colecciones
            self.messages = self.db.messages
            self.alerts = self.db.alerts
            self.statistics = self.db.statistics
            self.threat_patterns = self.db.threat_patterns
            
            # Crear índices
            await self._create_indexes()
            
            self._connected = True
            logger.info("✅ Conectado a MongoDB exitosamente")
            
        except Exception as e:
            logger.error(f"❌ Error al conectar a MongoDB: {e}")
            raise
    
    async def _create_indexes(self):
        """Crea índices para optimizar consultas."""
        try:
            # Índices para colección de mensajes
            await self.messages.create_index("timestamp")
            await self.messages.create_index("category")
            await self.messages.create_index("confidence")
            await self.messages.create_index([("user_id", 1), ("timestamp", -1)])
            
            # Índices para colección de alertas
            await self.alerts.create_index("timestamp")
            await self.alerts.create_index("severity")
            await self.alerts.create_index("event_type")
            
            logger.info("✅ Índices creados exitosamente")
            
        except Exception as e:
            logger.warning(f"⚠️ Error al crear índices: {e}")
    
    async def disconnect(self):
        """Cierra la conexión con MongoDB."""
        if self.client:
            self.client.close()
            self._connected = False
            logger.info("🔌 Desconectado de MongoDB")
    
    # ==================
    # Operaciones con Mensajes
    # ==================
    
    async def save_message(self, message_data: Dict[str, Any]) -> str:
        """
        Guarda un mensaje analizado.
        
        Args:
            message_data: Diccionario con los datos del mensaje
        
        Returns:
            ID del documento insertado
        """
        try:
            # Agregar timestamp si no existe
            if "timestamp" not in message_data:
                message_data["timestamp"] = datetime.utcnow()
            
            result = await self.messages.insert_one(message_data)
            logger.debug(f"💾 Mensaje guardado: {result.inserted_id}")
            return str(result.inserted_id)
            
        except Exception as e:
            logger.error(f"❌ Error al guardar mensaje: {e}")
            raise
    
    async def get_recent_messages(self, limit: int = 10, category: Optional[str] = None) -> List[Dict]:
        """
        Obtiene los mensajes más recientes.
        
        Args:
            limit: Número máximo de mensajes a retornar
            category: Filtrar por categoría (opcional)
        
        Returns:
            Lista de mensajes
        """
        try:
            query = {}
            if category:
                query["category"] = category
            
            cursor = self.messages.find(query).sort("timestamp", -1).limit(limit)
            messages = await cursor.to_list(length=limit)
            
            return messages
            
        except Exception as e:
            logger.error(f"❌ Error al obtener mensajes: {e}")
            return []
    
    async def count_messages_by_category(self) -> Dict[str, int]:
        """
        Cuenta mensajes por categoría.
        
        Returns:
            Diccionario con conteo por categoría
        """
        try:
            pipeline = [
                {
                    "$group": {
                        "_id": "$category",
                        "count": {"$sum": 1}
                    }
                }
            ]
            
            cursor = self.messages.aggregate(pipeline)
            results = await cursor.to_list(length=None)
            
            counts = {item["_id"]: item["count"] for item in results}
            return counts
            
        except Exception as e:
            logger.error(f"❌ Error al contar mensajes: {e}")
            return {}
    
    # ==================
    # Operaciones con Alertas de Suricata
    # ==================
    
    async def save_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Guarda una alerta de Suricata.
        
        Args:
            alert_data: Diccionario con los datos de la alerta
        
        Returns:
            ID del documento insertado
        """
        try:
            if "timestamp" not in alert_data:
                alert_data["timestamp"] = datetime.utcnow()
            
            result = await self.alerts.insert_one(alert_data)
            logger.debug(f"🚨 Alerta guardada: {result.inserted_id}")
            return str(result.inserted_id)
            
        except Exception as e:
            logger.error(f"❌ Error al guardar alerta: {e}")
            raise
    
    async def get_recent_alerts(self, limit: int = 10, severity: Optional[int] = None) -> List[Dict]:
        """
        Obtiene las alertas más recientes.
        
        Args:
            limit: Número máximo de alertas a retornar
            severity: Filtrar por severidad (opcional)
        
        Returns:
            Lista de alertas
        """
        try:
            query = {}
            if severity is not None:
                query["severity"] = {"$gte": severity}
            
            cursor = self.alerts.find(query).sort("timestamp", -1).limit(limit)
            alerts = await cursor.to_list(length=limit)
            
            return alerts
            
        except Exception as e:
            logger.error(f"❌ Error al obtener alertas: {e}")
            return []
    
    # ==================
    # Operaciones con Estadísticas
    # ==================
    
    async def update_statistics(self):
        """Actualiza las estadísticas del sistema."""
        try:
            stats = {
                "timestamp": datetime.utcnow(),
                "messages_by_category": await self.count_messages_by_category(),
                "total_messages": await self.messages.count_documents({}),
                "total_alerts": await self.alerts.count_documents({}),
            }
            
            # Guardar estadísticas
            await self.statistics.insert_one(stats)
            logger.debug("📊 Estadísticas actualizadas")
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Error al actualizar estadísticas: {e}")
            return {}
    
    async def get_latest_statistics(self) -> Optional[Dict]:
        """Obtiene las últimas estadísticas."""
        try:
            stats = await self.statistics.find_one(
                {},
                sort=[("timestamp", -1)]
            )
            return stats
            
        except Exception as e:
            logger.error(f"❌ Error al obtener estadísticas: {e}")
            return None
    
    # ==================
    # Operaciones con Patrones de Amenazas
    # ==================
    
    async def save_threat_pattern(self, pattern_data: Dict[str, Any]) -> str:
        """
        Guarda un patrón de amenaza detectado.
        
        Args:
            pattern_data: Diccionario con el patrón de amenaza
        
        Returns:
            ID del documento insertado
        """
        try:
            if "timestamp" not in pattern_data:
                pattern_data["timestamp"] = datetime.utcnow()
            
            result = await self.threat_patterns.insert_one(pattern_data)
            logger.debug(f"🎯 Patrón de amenaza guardado: {result.inserted_id}")
            return str(result.inserted_id)
            
        except Exception as e:
            logger.error(f"❌ Error al guardar patrón: {e}")
            raise
    
    async def get_threat_patterns(self, category: Optional[str] = None) -> List[Dict]:
        """
        Obtiene patrones de amenazas.
        
        Args:
            category: Filtrar por categoría (opcional)
        
        Returns:
            Lista de patrones
        """
        try:
            query = {}
            if category:
                query["category"] = category
            
            cursor = self.threat_patterns.find(query)
            patterns = await cursor.to_list(length=None)
            
            return patterns
            
        except Exception as e:
            logger.error(f"❌ Error al obtener patrones: {e}")
            return []
    
    # ==================
    # Utilidades
    # ==================
    
    def is_connected(self) -> bool:
        """Verifica si la conexión está activa."""
        return self._connected
    
    async def health_check(self) -> bool:
        """Verifica el estado de la conexión."""
        try:
            if not self.client:
                return False
            
            await self.client.admin.command('ping')
            return True
            
        except Exception:
            return False


# Instancia global de la base de datos
db = Database()


# Funciones de conveniencia
async def init_database():
    """Inicializa la conexión a la base de datos."""
    await db.connect()


async def close_database():
    """Cierra la conexión a la base de datos."""
    await db.disconnect()


if __name__ == "__main__":
    # Test de conexión
    async def test():
        await init_database()
        
        # Test de guardado de mensaje
        test_message = {
            "text": "Test message",
            "category": "SAFE",
            "confidence": 95,
            "user_id": "test_user"
        }
        
        msg_id = await db.save_message(test_message)
        print(f"Mensaje guardado: {msg_id}")
        
        # Test de obtención de mensajes
        messages = await db.get_recent_messages(limit=5)
        print(f"Mensajes recientes: {len(messages)}")
        
        # Test de estadísticas
        stats = await db.update_statistics()
        print(f"Estadísticas: {stats}")
        
        await close_database()
    
    asyncio.run(test())
