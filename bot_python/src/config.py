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
Tu tarea es analizar mensajes y clasificarlos en las siguientes categorías:
- PHISHING: Intentos de robo de credenciales o información personal
- SPAM: Mensajes comerciales no solicitados o contenido repetitivo
- SOCIAL_ENGINEERING: Manipulación psicológica para obtener información o acciones
- SAFE: Mensajes seguros sin amenazas

Debes responder SOLO con un JSON en el siguiente formato:
{
    "category": "PHISHING|SPAM|SOCIAL_ENGINEERING|SAFE",
    "confidence": 0-100,
    "reasoning": "Breve explicación de tu decisión",
    "indicators": ["lista", "de", "indicadores", "encontrados"]
}
"""
    
    ANALYSIS_PROMPT_TEMPLATE: str = """Analiza el siguiente mensaje y clasifícalo:

MENSAJE: {message}

Proporciona tu análisis en formato JSON."""
    
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
            errors.append("❌ TELEGRAM_BOT_TOKEN no está configurado")
        
        if not cls.MONGO_URI:
            errors.append("❌ MONGO_URI no está configurado")
        
        if not cls.OLLAMA_HOST:
            errors.append("❌ OLLAMA_HOST no está configurado")
        
        if errors:
            print("\n".join(errors))
            return False
        
        print("✅ Configuración validada correctamente")
        return True
    
    @classmethod
    def print_config(cls):
        """Imprime la configuración actual (sin secretos)."""
        print("\n" + "="*50)
        print("CONFIGURACIÓN DEL SISTEMA")
        print("="*50)
        print(f"🤖 Telegram Bot: {'✅ Configurado' if cls.TELEGRAM_BOT_TOKEN else '❌ No configurado'}")
        print(f"📦 MongoDB URI: {cls.MONGO_URI}")
        print(f"🧠 Ollama Host: {cls.OLLAMA_HOST}")
        print(f"🧠 Ollama Model: {cls.OLLAMA_MODEL}")
        print(f"📊 Log Level: {cls.LOG_LEVEL}")
        print(f"🎯 Threat Threshold: {cls.THREAT_THRESHOLD}")
        print(f"⚡ Cache: {'Enabled' if cls.ENABLE_CACHE else 'Disabled'}")
        print("="*50 + "\n")


# Validar configuración al importar
if __name__ == "__main__":
    Config.validate()
    Config.print_config()
