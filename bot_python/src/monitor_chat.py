"""
monitor_chat.py - Monitor de chat de Telegram con análisis de IA
Este módulo gestiona las interacciones con el bot de Telegram y la IA.
"""

import os
import re
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from telegram import Update
from telegram.ext import Application,CommandHandler, MessageHandler, filters, ContextTypes

from config import Config
from database import db
from ai_analyzer import ai_analyzer
from utils import format_threat_message, format_timestamp, get_time_ago, truncate_text

logger = logging.getLogger(__name__)


class MonitorChat:
    """Clase para gestionar el bot de Telegram y la integración con IA."""
    
    # Traducción de categorías internas a español para mostrar al usuario
    CATEGORY_LABELS_ES = {
        "PHISHING": "Phishing (Suplantación)",
        "SPAM": "Spam",
        "SOCIAL_ENGINEERING": "Ingeniería Social",
        "SAFE": "Seguro",
        "UNKNOWN": "Desconocido"
    }
    
    # Rate limiting: máximo 10 análisis por usuario cada 60 segundos
    RATE_LIMIT_MAX = 10
    RATE_LIMIT_WINDOW = 60  # segundos

    def __init__(self):
        self.telegram_token = Config.TELEGRAM_BOT_TOKEN
        self.app: Optional[Application] = None
        self.stats = {
            "messages_analyzed": 0,
            "threats_detected": 0,
            "safe_messages": 0
        }
        self._rate_limiter: Dict[int, List[datetime]] = {}
    
    async def iniciar(self):
        """Inicia el bot de Telegram."""
        try:
            logger.info("Iniciando monitor de chat...")
            
            # Verificar token
            if not self.telegram_token:
                logger.error("TELEGRAM_BOT_TOKEN no configurado")
                raise ValueError("Token de Telegram no configurado")
            
            # Inicializar IA y base de datos
            logger.info("Inicializando componentes...")
            await ai_analyzer.connect()
            await db.connect()
            
            # Configurar bot de Telegram
            self.app = Application.builder().token(self.telegram_token).build()
            self._registrar_handlers()
            
            logger.info("Monitor de chat iniciado correctamente")
            
            # Obtener info del bot
            bot_info = await self.app.bot.get_me()
            logger.info(f"Bot de Telegram: @{bot_info.username}")
            
            # Inicializar y ejecutar bot
            await self.app.initialize()
            await self.app.start()
            await self.app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
            
            # Mantener el bot ejecutándose
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Error al iniciar monitor de chat: {e}")
            raise
    
    def _registrar_handlers(self):
        """Registra los manejadores de comandos y mensajes."""
        # Comandos
        self.app.add_handler(CommandHandler("start", self.cmd_start))
        self.app.add_handler(CommandHandler("help", self.cmd_help))
        self.app.add_handler(CommandHandler("alertas", self.cmd_alertas))
        self.app.add_handler(CommandHandler("estado", self.cmd_estado))
        self.app.add_handler(CommandHandler("stats", self.cmd_stats))
        self.app.add_handler(CommandHandler("analizar", self.cmd_analizar))
        self.app.add_handler(CommandHandler("recientes", self.cmd_recientes))
        
        # Mensajes de texto - Escuchar en chats privados Y grupos
        self.app.add_handler(
            MessageHandler(
                (filters.TEXT & ~filters.COMMAND) & 
                (filters.ChatType.PRIVATE | filters.ChatType.GROUPS | filters.ChatType.SUPERGROUP),
                self.procesar_mensaje
            )
        )
        
        logger.info("Handlers registrados")

    def _check_rate_limit(self, user_id: int) -> bool:
        """Devuelve True si el usuario puede hacer una petición, False si ha superado el límite."""
        now = datetime.utcnow()
        ventana = now - timedelta(seconds=self.RATE_LIMIT_WINDOW)

        # Limpiar timestamps antiguos
        timestamps = self._rate_limiter.get(user_id, [])
        timestamps = [t for t in timestamps if t > ventana]

        if len(timestamps) >= self.RATE_LIMIT_MAX:
            self._rate_limiter[user_id] = timestamps
            return False

        timestamps.append(now)
        self._rate_limiter[user_id] = timestamps
        return True

    async def send_network_alert(self, alerta_data: dict):
        """Envía una alerta de red crítica de Suricata al chat de Telegram."""
        if not self.app:
            return
        try:
            severity_emoji = ["ℹ️", "⚠️", "🚨", "🔥"][min(alerta_data.get('severity', 1) - 1, 3)]
            mensaje = (
                f"{severity_emoji} <b>ALERTA DE RED CRÍTICA</b>\n\n"
                f"<b>Firma:</b> {self._escape_html(alerta_data.get('signature', 'Desconocida'))}\n"
                f"<b>Categoría:</b> {self._escape_html(alerta_data.get('category', 'Desconocida'))}\n"
                f"<b>Origen:</b> {alerta_data.get('source_ip', '?')}:{alerta_data.get('source_port', '?')}\n"
                f"<b>Destino:</b> {alerta_data.get('dest_ip', '?')}:{alerta_data.get('dest_port', '?')}\n"
                f"<b>Protocolo:</b> {alerta_data.get('protocol', '?')}"
            )
            await self.app.bot.send_message(
                chat_id=Config.TELEGRAM_ALERT_CHAT_ID,
                text=mensaje,
                parse_mode='HTML'
            )
        except Exception as e:
            logger.error(f"Error enviando alerta de red a Telegram: {e}")

    # ==================
    # Comandos del Bot
    # ==================
    
    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /start."""
        mensaje = """
**Sistema de Ciberseguridad Inteligente**

¡Bienvenido! Soy tu asistente de seguridad para Telegram.

Analizo mensajes en tiempo real para detectar:
Phishing
Spam
Ingeniería Social

**Comandos disponibles:**
/help - Ver ayuda completa
/alertas - Ver últimas amenazas detectadas
/estado - Estado del sistema
/stats - Estadísticas de análisis
/analizar <texto> - Analizar un mensaje específico
/recientes - Ver mensajes recientes analizados

Envía cualquier mensaje y lo analizaré automáticamente.
"""
        await update.message.reply_text(mensaje, parse_mode='Markdown')
    
    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /help."""
        mensaje = """
**Ayuda del Sistema de Ciberseguridad**

**Comandos:**

/start - Mensaje de bienvenida
/help - Esta ayuda
/alertas [cantidad] - Ver últimas amenazas (default: 5)
/estado - Ver estado de servicios
/stats - Ver estadísticas de análisis
/analizar <texto> - Analizar mensaje específico
/recientes [tipo] - Ver mensajes recientes
  Tipos: phishing, spam, social, safe

**Análisis Automático:**
Envía cualquier mensaje y será analizado automáticamente.
Recibirás un informe con:
- Categoría de amenaza (si aplica)
- Nivel de confianza
- Indicadores detectados
- Recomendaciones

**Categorías de Amenazas:**
PHISHING - Robo de credenciales
SPAM - Contenido no solicitado
SOCIAL_ENGINEERING - Manipulación psicológica
SAFE - Mensaje seguro
"""
        await update.message.reply_text(mensaje, parse_mode='Markdown')
    
    async def cmd_alertas(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /alertas."""
        try:
            # Obtener cantidad de alertas (default 5)
            cantidad = 5
            if context.args:
                try:
                    cantidad = int(context.args[0])
                    cantidad = min(cantidad, 20)  # Máximo 20
                except ValueError:
                    await update.message.reply_text("Cantidad inválida. Usando 5.")
            
            # Obtener mensajes peligrosos
            threats = await db.get_recent_messages(limit=cantidad * 3)  # Obtener más para filtrar
            
            # Filtrar solo amenazas
            threats = [m for m in threats if m.get('category') != 'SAFE'][:cantidad]
            
            if not threats:
                await update.message.reply_text("No hay amenazas recientes detectadas.")
                return
            
            mensaje = f"Últimas {len(threats)} Amenazas Detectadas\n\n"
            
            for i, threat in enumerate(threats, 1):
                categoria = threat.get('category', 'UNKNOWN')
                categoria_es = self.CATEGORY_LABELS_ES.get(categoria, categoria)
                confianza = threat.get('confidence', 0)
                texto = truncate_text(threat.get('text', 'N/A'), 80)
                timestamp = threat.get('timestamp', datetime.utcnow())
                
                emoji = {"PHISHING": "🎣", "SPAM": "📧", "SOCIAL_ENGINEERING": "🎭"}.get(categoria, "⚠️")
                
                mensaje += f"{i}. {emoji} **{categoria_es}** (Certeza: {confianza}%)\n"
                mensaje += f"   _{get_time_ago(timestamp)}_\n"
                mensaje += f"   `{texto}`\n\n"
            
            await update.message.reply_text(mensaje, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error en cmd_alertas: {e}")
            await update.message.reply_text("Error al obtener alertas")
    
    async def cmd_estado(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /estado."""
        try:
            # Verificar estado de componentes
            db_status = "Conectado" if await db.health_check() else "Desconectado"
            ai_status = "Conectado" if await ai_analyzer.health_check() else "Desconectado"
            
            mensaje = f"""
Estado del Sistema

Componentes:
MongoDB: {db_status}
Ollama IA: {ai_status}
Bot Telegram: Activo

**Modelo IA:** {Config.OLLAMA_MODEL}
**Umbral de Amenaza:** {Config.THREAT_THRESHOLD}%

**Estadísticas de Sesión:**
Mensajes analizados: {self.stats['messages_analyzed']}
Amenazas detectadas: {self.stats['threats_detected']}
Mensajes seguros: {self.stats['safe_messages']}
"""
            await update.message.reply_text(mensaje, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error en cmd_estado: {e}")
            await update.message.reply_text("Error al obtener estado")
    
    async def cmd_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /stats."""
        try:
            # Obtener estadísticas de la base de datos
            stats = await db.count_messages_by_category()
            total = sum(stats.values())
            
            if total == 0:
                await update.message.reply_text("No hay estadísticas disponibles aún.")
                return
            
            mensaje = "Estadísticas Globales\n\n"
            mensaje += f"Total de mensajes: {total}\n\n"
            
            for category in ['PHISHING', 'SPAM', 'SOCIAL_ENGINEERING', 'SAFE']:
                count = stats.get(category, 0)
                percentage = (count / total * 100) if total > 0 else 0
                category_es = self.CATEGORY_LABELS_ES.get(category, category)
                emoji = {"PHISHING": "🎣", "SPAM": "📧", "SOCIAL_ENGINEERING": "🎭", "SAFE": "✅"}.get(category, "📁")
                mensaje += f"{emoji} **{category_es}:** {count} ({percentage:.1f}%)\n"
            
            await update.message.reply_text(mensaje, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error en cmd_stats: {e}")
            await update.message.reply_text("Error al obtener estadísticas")
    
    async def cmd_analizar(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /analizar."""
        if not context.args:
            await update.message.reply_text("Uso: /analizar <mensaje a analizar>")
            return

        if not self._check_rate_limit(update.effective_user.id):
            await update.message.reply_text(
                f"⏳ Has superado el límite de {self.RATE_LIMIT_MAX} análisis "
                f"por minuto. Espera un momento."
            )
            return

        mensaje_analizar = " ".join(context.args)
        await update.message.reply_text("Analizando mensaje...")
        
        # Procesar mensaje
        await self._analizar_y_responder(update, mensaje_analizar, is_command=True)
    
    async def cmd_recientes(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Manejador del comando /recientes."""
        try:
            # Obtener tipo de filtro
            category = None
            if context.args:
                tipo = context.args[0].upper()
                category_map = {
                    'PHISHING': 'PHISHING',
                    'SPAM': 'SPAM',
                    'SOCIAL': 'SOCIAL_ENGINEERING',
                    'SAFE': 'SAFE'
                }
                category = category_map.get(tipo)
            
            # Obtener mensajes
            messages = await db.get_recent_messages(limit=10, category=category)
            
            if not messages:
                await update.message.reply_text("No hay mensajes recientes.")
                return
            
            mensaje = f"Mensajes Recientes"
            if category:
                mensaje += f" - {category}"
            mensaje += "**\n\n"
            
            for i, msg in enumerate(messages, 1):
                categoria = msg.get('category', 'UNKNOWN')
                categoria_es = self.CATEGORY_LABELS_ES.get(categoria, categoria)
                texto = truncate_text(msg.get('text', 'N/A'), 60)
                timestamp = msg.get('timestamp', datetime.utcnow())
                
                emoji = {"PHISHING": "🎣", "SPAM": "📧", "SOCIAL_ENGINEERING": "🎭", "SAFE": "✅"}.get(categoria, "📁")
                
                mensaje += f"{i}. {emoji} [{categoria_es}] `{texto}`\n"
                mensaje += f"   _{get_time_ago(timestamp)}_\n\n"
            
            await update.message.reply_text(mensaje, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error en cmd_recientes: {e}")
            await update.message.reply_text("Error al obtener mensajes")
    
    # ==================
    # Procesamiento de Mensajes
    # ==================
    
    async def procesar_mensaje(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Procesa mensajes de texto automáticamente."""
        if not self._check_rate_limit(update.effective_user.id):
            await update.message.reply_text(
                f"⏳ Has superado el límite de {self.RATE_LIMIT_MAX} análisis "
                f"por minuto. Espera un momento."
            )
            return
        mensaje = update.message.text
        await self._analizar_y_responder(update, mensaje)
    
    async def _analizar_y_responder(self, update: Update, mensaje: str, is_command: bool = False):
        """Analiza un mensaje y envía la respuesta."""
        try:
            # Analizar con IA
            resultado = await ai_analyzer.analyze_message(mensaje)
            
            # Actualizar estadísticas
            self.stats['messages_analyzed'] += 1
            if resultado['category'] != 'SAFE':
                self.stats['threats_detected'] += 1
            else:
                self.stats['safe_messages'] += 1
            
            # Guardar en base de datos
            await db.save_message({
                "text": mensaje,
                "category": resultado['category'],
                "confidence": resultado['confidence'],
                "reasoning": resultado['reasoning'],
                "indicators": resultado['indicators'],
                "risk_score": resultado['risk_score'],
                "metadata": resultado.get('metadata', {}),
                "user_id": str(update.effective_user.id),
                "username": update.effective_user.username,
                "timestamp": datetime.utcnow()
            })
            
            # Formatear respuesta
            respuesta = self._formatear_respuesta(resultado)
            
            await update.message.reply_text(respuesta, parse_mode='HTML')
            
            # Si es una amenaza severa, enviar alerta adicional
            if resultado['category'] != 'SAFE' and resultado['confidence'] >= Config.THREAT_THRESHOLD:
                categoria_es = self.CATEGORY_LABELS_ES.get(resultado['category'], resultado['category'])
                alerta = f"<b>⚠️ ALERTA DE SEGURIDAD</b>\n\n"
                alerta += f"Se detectó una amenaza de tipo <b>{categoria_es}</b> "
                alerta += f"con {resultado['confidence']}% de certeza.\n\n"
                alerta += "<b>Recomendación:</b> No interactúes con este mensaje."
                
                await update.message.reply_text(alerta, parse_mode='HTML')
            
        except Exception as e:
            logger.error(f"Error al procesar mensaje: {e}")
            await update.message.reply_text("Error al analizar el mensaje. Intenta nuevamente.")
    
    def _formatear_respuesta(self, resultado: dict) -> str:
        """Formatea el resultado del análisis para mostrar al usuario (HTML)."""
        categoria = resultado['category']
        categoria_es = self.CATEGORY_LABELS_ES.get(categoria, categoria)
        confianza = resultado['confidence']
        razon = self._escape_html(resultado['reasoning'])
        indicadores = resultado['indicators']
        risk_score = resultado.get('risk_score', 0)
        
        # Emoji según categoría
        emoji_map = {
            "PHISHING": "🎣",
            "SPAM": "📧",
            "SOCIAL_ENGINEERING": "🎭",
            "SAFE": "✅",
            "UNKNOWN": "❓"
        }
        emoji = emoji_map.get(categoria, "⚠️")
        
        # Construir mensaje en HTML (completamente en español)
        mensaje = f"{emoji} <b>Análisis Completado</b>\n\n"
        mensaje += f"<b>Categoría:</b> {categoria_es}\n"
        mensaje += f"<b>Certeza del análisis:</b> {confianza}%\n"
        mensaje += f"<b>Nivel de peligrosidad:</b> {risk_score}/100\n\n"
        mensaje += f"<b>Análisis:</b>\n{razon}\n"
        
        if indicadores:
            mensaje += f"\n<b>Indicadores Detectados:</b>\n"
            for ind in indicadores[:5]:  # Máximo 5 indicadores
                ind_escaped = self._escape_html(ind)
                mensaje += f"• {ind_escaped}\n"
        
        # Recomendación
        if categoria != 'SAFE':
            mensaje += f"\n<b>Recomendación:</b> Procede con precaución."
        else:
            mensaje += f"\n<b>Recomendación:</b> Este mensaje parece seguro."
        
        return mensaje
    
    def _escape_html(self, text: str) -> str:
        """Escapa caracteres especiales de HTML para Telegram."""
        if not text:
            return ""
        # Caracteres reservados en HTML
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text


# Instancia global
monitor_chat = MonitorChat()


if __name__ == "__main__":
    import asyncio
    
    async def test():
        await monitor_chat.iniciar()
    
    asyncio.run(test())

