"""
main.py - Código principal del bot de ciberseguridad
Este script inicializa y coordina los módulos de monitoreo.
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime

# Importar configuración primero
from config import Config

# Configurar logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format=Config.LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'logs/sistema_{datetime.now().strftime("%Y%m%d")}.log', encoding='utf-8')
    ]
)

logger = logging.getLogger(__name__)

# Importar módulos
from monitor_red import monitor_red
from monitor_chat import monitor_chat
from database import db
from ai_analyzer import ai_analyzer


class SistemaCiberseguridad:
    """Clase principal del sistema de ciberseguridad."""
    
    def __init__(self):
        self.running = False
        self.tasks = []
    
    async def inicializar(self):
        """Inicializa todos los componentes del sistema."""
        try:
            logger.info("="*60)
            logger.info("🛡️  SISTEMA DE CIBERSEGURIDAD INTELIGENTE EN TELEGRAM")
            logger.info("="*60)
            logger.info("")
            
            # Validar configuración
            if not Config.validate():
                logger.error("❌ Configuración inválida. Abortando...")
                return False
            
            # Mostrar configuración
            Config.print_config()
            
            logger.info("🔧 Inicializando componentes del sistema...")
            logger.info("")
            
            # Inicializar base de datos
            logger.info("1️⃣  Conectando a MongoDB...")
            await db.connect()
            logger.info("✅ MongoDB conectado")
            logger.info("")
            
            # Inicializar IA
            logger.info("2️⃣  Conectando a Ollama...")
            await ai_analyzer.connect()
            logger.info("✅ Ollama conectado")
            logger.info("")
            
            logger.info("="*60)
            logger.info("✅ TODOS LOS COMPONENTES INICIALIZADOS CORRECTAMENTE")
            logger.info("="*60)
            logger.info("")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error durante la inicialización: {e}")
            return False
    
    async def iniciar(self):
        """Inicia el sistema completo."""
        try:
            # Inicializar componentes
            if not await self.inicializar():
                logger.error("❌ Falló la inicialización. Sistema abortado.")
                return
            
            self.running = True
            
            logger.info("🚀 Iniciando monitores...")
            logger.info("")
            
            # Crear tareas de monitoreo
            task_red = asyncio.create_task(
                self._run_monitor_red(),
                name="MonitorRed"
            )
            
            task_chat = asyncio.create_task(
                self._run_monitor_chat(),
                name="MonitorChat"
            )
            
            self.tasks = [task_red, task_chat]
            
            logger.info("="*60)
            logger.info("🟢 SISTEMA EN FUNCIONAMIENTO")
            logger.info("="*60)
            logger.info("")
            logger.info("ℹ️  Presiona Ctrl+C para detener el sistema")
            logger.info("")
            
            # Esperar a que las tareas terminen (o sean canceladas)
            await asyncio.gather(*self.tasks, return_exceptions=True)
            
        except KeyboardInterrupt:
            logger.info("\n⚠️  Interrupción detectada (Ctrl+C)")
            await self.detener()
        except Exception as e:
            logger.error(f"❌ Error crítico en el sistema: {e}")
            await self.detener()
    
    async def _run_monitor_red(self):
        """Ejecuta el monitor de red con manejo de errores."""
        try:
            logger.info("👁️  Monitor de Red: Iniciando...")
            await monitor_red.iniciar()
        except Exception as e:
            logger.error(f"❌ Error en Monitor de Red: {e}")
            if self.running:
                logger.info("🔄 Reintentando en 10 segundos...")
                await asyncio.sleep(10)
                if self.running:
                    await self._run_monitor_red()
    
    async def _run_monitor_chat(self):
        """Ejecuta el monitor de chat con manejo de errores."""
        try:
            logger.info("💬 Monitor de Chat: Iniciando...")
            await monitor_chat.iniciar()
        except Exception as e:
            logger.error(f"❌ Error en Monitor de Chat: {e}")
            if self.running:
                logger.info("🔄 Reintentando en 10 segundos...")
                await asyncio.sleep(10)
                if self.running:
                    await self._run_monitor_chat()
    
    async def detener(self):
        """Detiene el sistema de forma ordenada."""
        logger.info("")
        logger.info("="*60)
        logger.info("🛑 DETENIENDO SISTEMA DE CIBERSEGURIDAD")
        logger.info("="*60)
        
        self.running = False
        
        # Cancelar tareas
        for task in self.tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Cerrar conexiones
        logger.info("🔌 Cerrando conexiones...")
        
        try:
            await db.disconnect()
            logger.info("✅ MongoDB desconectado")
        except Exception as e:
            logger.error(f"⚠️  Error al cerrar MongoDB: {e}")
        
        # Detener observer de monitor_red si existe
        try:
            monitor_red.detener()
        except Exception as e:
            logger.error(f"⚠️  Error al detener monitor de red: {e}")
        
        logger.info("")
        logger.info("="*60)
        logger.info("✅ SISTEMA DETENIDO CORRECTAMENTE")
        logger.info("="*60)


async def main():
    """Función principal que inicia el sistema."""
    sistema = SistemaCiberseguridad()
    
    # Configurar manejadores de señales para shutdown graceful
    def signal_handler(signum, frame):
        logger.info(f"\n⚠️  Señal recibida: {signal.Signals(signum).name}")
        asyncio.create_task(sistema.detener())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Iniciar sistema
    await sistema.iniciar()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n👋 Sistema finalizado por el usuario")
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        sys.exit(1)

