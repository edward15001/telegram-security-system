"""
config.py - Configuración centralizada del sistema
Este módulo gestiona todas las variables de configuración y entorno.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()


class Config:
    """Clase de configuración del sistema."""
    
    # ==================
    # Telegram
    # ==================
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    # Chat ID donde se enviarán las alertas críticas de red (tu chat o un grupo de admins)
    TELEGRAM_ALERT_CHAT_ID: Optional[int] = int(os.getenv("TELEGRAM_ALERT_CHAT_ID", "0")) or None
    
    # ==================
    # MongoDB
    # ==================
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://mongodb:27017/ciberseguridad")
    MONGO_DB_NAME: str = "ciberseguridad"
    
    # ==================
    # Ollama
    # ==================
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://ollama:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")
    OLLAMA_TIMEOUT: int = 60  # Timeout en segundos
    
    # ==================
    # Logging
    # ==================
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # ==================
    # Clasificación de Amenazas
    # ==================
    THREAT_THRESHOLD: int = int(os.getenv("THREAT_THRESHOLD", "70"))
    
    # Umbrales específicos por categoría
    PHISHING_THRESHOLD: int = 75
    SPAM_THRESHOLD: int = 65
    SOCIAL_ENGINEERING_THRESHOLD: int = 70
    
    # ==================
    # Suricata
    # ==================
    SURICATA_LOGS_PATH: str = "/app/logs"
    SURICATA_EVE_JSON: str = "eve.json"
    
    # ==================
    # Prompts de IA
    # ==================
    SYSTEM_PROMPT: str = """Eres un experto en ciberseguridad especializado en detectar amenazas en mensajes.
Tu tarea es analizar mensajes y clasificarlos CORRECTAMENTE en las siguientes categorías:

IMPORTANTE: SIEMPRE debes responder COMPLETAMENTE EN ESPAÑOL, sin importar en qué idioma esté escrito el mensaje que analizas. Tanto el campo "reasoning" como los "indicators" deben estar escritos en español.

CATEGORÍAS (lee con atención las diferencias):

1. PHISHING: Intentos de ROBAR CREDENCIALES o datos sensibles.
   - Siempre incluye enlaces a sitios web falsos que imitan bancos, redes sociales, etc.
   - Pide explícitamente: contraseñas, números de tarjeta, PIN, códigos de verificación
   - Ejemplos: "Tu cuenta bancaria será suspendida, haz clic aquí para verificar", "Netflix: actualiza tu forma de pago en http://falso.com"

2. SOCIAL_ENGINEERING: Manipulación EMOCIONAL/PSICOLÓGICA para obtener dinero o acciones.
   - NO tiene enlaces a páginas de login
   - Usa pretextos emocionales: emergencias familiares, problemas urgentes, suplantación de identidad
   - Pide transferencias de dinero, favores, o acciones directas
   - Ejemplos: "Hola mamá/papá, este es mi nuevo número, necesito que me envíes dinero urgente", "Soy tu jefe, necesito que compres tarjetas de regalo ahora"

3. SPAM: Contenido comercial NO SOLICITADO o promocional.
   - Ofertas, descuentos, sorteos, oportunidades de negocio
   - Cripto scams, esquemas piramidales, contenido para adultos
   - Enlaces a grupos de Telegram, canales, etc.
   - Ejemplos: "Gana $5000 al día desde casa", "Pack filtrado de famosa tiktoker"

4. SAFE: Mensajes legítimos y seguros sin amenazas.

REGLA IMPORTANTE: 
- Si el mensaje pide CREDENCIALES o tiene enlaces a PÁGINAS DE LOGIN → PHISHING
- Si el mensaje usa EMOTIVIDAD/URGENCIA para pedir DINERO o ACCIONES → SOCIAL_ENGINEERING
- Si el mensaje es PUBLICIDAD o CONTENIDO NO SOLICITADO → SPAM

Responde SOLO con un JSON (SIEMPRE EN ESPAÑOL):
{
    "category": "PHISHING|SPAM|SOCIAL_ENGINEERING|SAFE",
    "confidence": 0-100,
    "reasoning": "Explicación EN ESPAÑOL de tu decisión basada en los criterios anteriores",
    "indicators": ["lista", "de", "indicadores", "en español"]
}

CALIBRACIÓN DE CONFIANZA (muy importante):
- 90-100: SOLO para amenazas OBVIAS con múltiples indicadores claros (ej: URL falsa + solicitud de contraseña + urgencia)
- 70-89: Amenaza probable con varios indicadores presentes
- 50-69: Sospechoso pero sin evidencia contundente
- 30-49: Indicios leves, podría ser legítimo
- 0-29: Mensaje probablemente seguro
NO des confianza de 85%+ a menos que haya evidencia muy clara y múltiple de amenaza.
"""
    
    ANALYSIS_PROMPT_TEMPLATE: str = """Analiza el siguiente mensaje y clasifícalo según los criterios establecidos.
IMPORTANTE: Tu respuesta DEBE estar COMPLETAMENTE EN ESPAÑOL, incluso si el mensaje está en inglés u otro idioma.

MENSAJE A ANALIZAR:
{message}

RECUERDA:
- PHISHING = robo de credenciales, enlaces a login falsos
- SOCIAL_ENGINEERING = manipulación emocional, pedir dinero/favores
- SPAM = publicidad, ofertas, contenido no solicitado

Proporciona tu análisis en formato JSON. Todo el contenido del JSON (reasoning e indicators) debe estar EN ESPAÑOL."""
    
    # ==================
    # Caché
    # ==================
    ENABLE_CACHE: bool = True
    CACHE_TTL: int = 3600  # Time to live en segundos (1 hora)
    
    # ==================
    # Rendimiento
    # ==================
    MAX_CONCURRENT_ANALYSES: int = 5
    MESSAGE_QUEUE_SIZE: int = 100
    
    # ==================
    # Validación
    # ==================
    @classmethod
    def validate(cls) -> bool:
        """Valida que las configuraciones críticas estén presentes."""
        errors = []
        
        if not cls.TELEGRAM_BOT_TOKEN:
            errors.append("TELEGRAM_BOT_TOKEN no está configurado")
        
        if not cls.MONGO_URI:
            errors.append("MONGO_URI no está configurado")
        
        if not cls.OLLAMA_HOST:
            errors.append("OLLAMA_HOST no está configurado")
        
        if errors:
            print("\n".join(errors))
            return False
        
        print("Configuración validada correctamente")
        return True
    
    @classmethod
    def print_config(cls):
        """Imprime la configuración actual (sin secretos)."""
        print("\n" + "="*50)
        print("CONFIGURACIÓN DEL SISTEMA")
        print("="*50)
        print(f"Telegram Bot: {'Configurado' if cls.TELEGRAM_BOT_TOKEN else 'No configurado'}")
        print(f"MongoDB URI: {cls.MONGO_URI}")
        print(f"Ollama Host: {cls.OLLAMA_HOST}")
        print(f"Ollama Model: {cls.OLLAMA_MODEL}")
        print(f"Log Level: {cls.LOG_LEVEL}")
        print(f"Threat Threshold: {cls.THREAT_THRESHOLD}")
        print(f"Cache: {'Enabled' if cls.ENABLE_CACHE else 'Disabled'}")
        print("="*50 + "\n")


# Validar configuración al importar
if __name__ == "__main__":
    Config.validate()
    Config.print_config()
