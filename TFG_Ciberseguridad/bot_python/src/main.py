"""
main.py - Código principal del bot de ciberseguridad
Este script inicializa y coordina los módulos de monitoreo.
"""

import asyncio
from monitor_red import MonitorRed
from monitor_chat import MonitorChat


async def main():
    """Función principal que inicia los monitores."""
    print("🚀 Iniciando bot de ciberseguridad...")
    
    # TODO: Inicializar el monitor de red (logs de Suricata)
    monitor_red = MonitorRed()
    
    # TODO: Inicializar el monitor de chat (Telegram + IA)
    monitor_chat = MonitorChat()
    
    # TODO: Ejecutar ambos monitores de forma concurrente
    await asyncio.gather(
        monitor_red.iniciar(),
        monitor_chat.iniciar()
    )


if __name__ == "__main__":
    asyncio.run(main())
