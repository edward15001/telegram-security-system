"""
monitor_chat.py - Script que maneja la comunicación con Telegram e IA
Este módulo gestiona las interacciones con el bot de Telegram y la IA.
"""

import os
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from openai import OpenAI


class MonitorChat:
    """Clase para gestionar el bot de Telegram y la integración con IA."""
    
    def __init__(self):
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.openai_client = None
        self.app = None
    
    async def iniciar(self):
        """Inicia el bot de Telegram."""
        print("💬 Iniciando monitor de chat...")
        
        # TODO: Configurar el cliente de OpenAI
        if self.openai_api_key:
            self.openai_client = OpenAI(api_key=self.openai_api_key)
        
        # TODO: Configurar y ejecutar el bot de Telegram
        if self.telegram_token:
            self.app = Application.builder().token(self.telegram_token).build()
            self._registrar_handlers()
            await self.app.run_polling()
    
    def _registrar_handlers(self):
        """Registra los manejadores de comandos y mensajes."""
        self.app.add_handler(CommandHandler("start", self.cmd_start))
        self.app.add_handler(CommandHandler("alertas", self.cmd_alertas))
        self.app.add_handler(CommandHandler("estado", self.cmd_estado))
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.procesar_mensaje))
    
    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /start."""
        await update.message.reply_text(
            "🛡️ ¡Hola! Soy tu asistente de ciberseguridad.\n"
            "Comandos disponibles:\n"
            "/alertas - Ver últimas alertas\n"
            "/estado - Estado del sistema"
        )
    
    async def cmd_alertas(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /alertas."""
        # TODO: Implementar obtención y envío de alertas
        await update.message.reply_text("📋 Obteniendo últimas alertas...")
    
    async def cmd_estado(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /estado."""
        # TODO: Implementar verificación de estado
        await update.message.reply_text("✅ Sistema operativo")
    
    async def procesar_mensaje(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Procesa mensajes de texto y responde usando IA."""
        # TODO: Implementar integración con OpenAI
        mensaje = update.message.text
        respuesta = await self.consultar_ia(mensaje)
        await update.message.reply_text(respuesta)
    
    async def consultar_ia(self, mensaje: str) -> str:
        """Consulta a la IA para obtener una respuesta."""
        if not self.openai_client:
            return "⚠️ IA no configurada"
        
        # TODO: Implementar llamada a OpenAI
        return "🤖 Respuesta de IA pendiente de implementar"
