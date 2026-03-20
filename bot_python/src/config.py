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
    TELEGRAM_ALERT_CHAT_ID: Optional[int] = int(os.getenv("TELEGRAM_CHAT_ID", "0")) or None
    
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
    OLLAMA_TIMEOUT: int = 180  # Timeout en segundos (aumentado para Raspberry Pi)
    
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
    SYSTEM_PROMPT: str = """Eres un detector de amenazas en mensajes. Clasifica en una de estas categorías:
- PHISHING: roba credenciales con enlaces a páginas de login falsas
- SOCIAL_ENGINEERING: manipulación emocional para pedir dinero o acciones urgentes
- SPAM: publicidad no solicitada, ofertas, sorteos, cripto
- SAFE: mensaje legítimo sin amenaza

Responde únicamente con JSON válido en español."""

    ANALYSIS_PROMPT_TEMPLATE: str = """Clasifica este mensaje:

{message}

Responde con este JSON exacto (sin texto adicional):
{{"category": "PHISHING|SPAM|SOCIAL_ENGINEERING|SAFE", "confidence": 0-100, "reasoning": "motivo en español", "indicators": ["indicador1"]}}"""
    
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
