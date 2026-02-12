"""
utils.py - Funciones auxiliares y utilidades
Contiene funciones de ayuda para validación, extracción y formateo.
"""

import re
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ==================
# Validación de URLs
# ==================

def normalize_obfuscated_text(text: str) -> str:
    """
    Normaliza texto eliminando espacios en patrones comunes de URLs ofuscadas.
    
    Ejemplos:
        't . me / +abc' -> 't.me/+abc'
        'telegram . me / grupo' -> 'telegram.me/grupo'
    """
    normalized = text
    
    # Patrones de dominios comunes que se ofuscan con espacios
    obfuscation_patterns = [
        # Telegram
        (r't\s*\.\s*me\s*/\s*', 't.me/'),
        (r'telegram\s*\.\s*me\s*/\s*', 'telegram.me/'),
        (r'telegram\s*\.\s*org\s*/\s*', 'telegram.org/'),
        # Otros dominios comunes
        (r'bit\s*\.\s*ly\s*/\s*', 'bit.ly/'),
        (r'wa\s*\.\s*me\s*/\s*', 'wa.me/'),
        (r'discord\s*\.\s*gg\s*/\s*', 'discord.gg/'),
    ]
    
    for pattern, replacement in obfuscation_patterns:
        normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
    
    return normalized


def extract_urls(text: str) -> List[str]:
    """
    Extrae todas las URLs de un texto, incluyendo URLs ofuscadas.
    
    Args:
        text: Texto del que extraer URLs
    
    Returns:
        Lista de URLs encontradas
    """
    # Primero normalizar texto para detectar URLs ofuscadas
    normalized_text = normalize_obfuscated_text(text)
    
    # Patrón para detectar URLs con protocolo
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, normalized_text)
    
    # También buscar URLs sin protocolo (www.)
    no_protocol_pattern = r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls_no_protocol = re.findall(no_protocol_pattern, normalized_text)
    urls.extend(['http://' + url for url in urls_no_protocol])
    
    # Buscar enlaces de Telegram (t.me, telegram.me)
    telegram_urls = extract_telegram_links(normalized_text)
    urls.extend(telegram_urls)
    
    return list(set(urls))  # Eliminar duplicados


def extract_telegram_links(text: str) -> List[str]:
    """
    Extrae específicamente enlaces de Telegram del texto.
    Detecta formatos como: t.me/grupo, telegram.me/+invite, etc.
    
    Args:
        text: Texto del que extraer enlaces
    
    Returns:
        Lista de enlaces de Telegram encontrados
    """
    # Normalizar primero para capturar versiones ofuscadas
    normalized = normalize_obfuscated_text(text)
    
    # Patrones para enlaces de Telegram
    telegram_patterns = [
        r't\.me/[+]?[a-zA-Z0-9_-]+',
        r'telegram\.me/[+]?[a-zA-Z0-9_-]+',
        r'telegram\.org/[+]?[a-zA-Z0-9_-]+',
    ]
    
    links = []
    for pattern in telegram_patterns:
        matches = re.findall(pattern, normalized, re.IGNORECASE)
        links.extend(['https://' + m if not m.startswith('http') else m for m in matches])
    
    return list(set(links))


def has_obfuscated_urls(text: str) -> bool:
    """
    Detecta si el texto contiene URLs intencionalmente ofuscadas.
    
    Returns:
        True si hay indicios de ofuscación de URLs
    """
    # Patrones de ofuscación común
    obfuscation_indicators = [
        r't\s+\.\s+me',  # t . me
        r'telegram\s+\.\s+me',
        r'bit\s+\.\s+ly',
        r'wa\s+\.\s+me',
        r'discord\s+\.\s+gg',
        r'\[\s*\.\s*\]',  # [.] o [ . ]
        r'\(\s*\.\s*\)',  # (.) o ( . )
        r'dot\s+',  # "dot" en lugar de "."
        r'\s+dot\s+',
    ]
    
    for pattern in obfuscation_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    return False


def is_suspicious_url(url: str) -> bool:
    """
    Verifica si una URL parece sospechosa.
    
    Args:
        url: URL a verificar
    
    Returns:
        True si la URL es sospechosa
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Dominios sospechosos comunes
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # URLs con IP en lugar de dominio
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, domain):
            return True
        
        # Dominios muy largos (posible ofuscación)
        if len(domain) > 50:
            return True
        
        # Múltiples subdominios (posible typosquatting)
        if domain.count('.') > 3:
            return True
        
        # Palabras clave sospechosas en el dominio
        suspicious_keywords = [
            'login', 'signin', 'verify', 'account', 'security', 
            'update', 'confirm', 'validate', 'bank', 'paypal',
            'secure', 'suspended', 'limited', 'unusual'
        ]
        if any(keyword in domain for keyword in suspicious_keywords):
            return True
        
        return False
        
    except Exception as e:
        logger.warning(f"Error al analizar URL {url}: {e}")
        return False


def is_url_shortener(url: str) -> bool:
    """
    Verifica si una URL es de un servicio de acortamiento.
    
    Args:
        url: URL a verificar
    
    Returns:
        True si es un acortador de URLs
    """
    shortener_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'short.io', 'tiny.cc',
        'rebrand.ly', 'cutt.ly', 's.id'
    ]
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return any(shortener in domain for shortener in shortener_domains)
    except:
        return False


# ==================
# Extracción de Patrones
# ==================

def extract_phone_numbers(text: str) -> List[str]:
    """Extrae números de teléfono del texto."""
    # Patrón para números de teléfono internacionales
    phone_pattern = r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,5}[-\s\.]?[0-9]{1,5}'
    phones = re.findall(phone_pattern, text)
    return [phone.strip() for phone in phones if len(phone.strip()) >= 9]


def extract_emails(text: str) -> List[str]:
    """Extrae direcciones de email del texto."""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def extract_crypto_addresses(text: str) -> List[str]:
    """Extrae direcciones de criptomonedas del texto."""
    # Patrón para Bitcoin
    btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    btc_addresses = re.findall(btc_pattern, text)
    
    # Patrón para Ethereum
    eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
    eth_addresses = re.findall(eth_pattern, text)
    
    return btc_addresses + eth_addresses


# ==================
# Análisis de Texto
# ==================

def count_suspicious_keywords(text: str) -> int:
    """
    Cuenta palabras clave sospechosas en el texto.
    
    Args:
        text: Texto a analizar
    
    Returns:
        Número de palabras clave sospechosas encontradas
    """
    text_lower = text.lower()
    
    suspicious_keywords = [
        # Urgencia
        'urgente', 'inmediato', 'ahora', 'rápido', 'último día',
        'antes de que', 'solo por hoy', 'últimas horas', 'no te pierdas',
        
        # Premios/Sorteos
        'ganador', 'premio', 'gratis', 'regalo', 'sorteo', 'lotería',
        'entrada gratis', 'acceso gratis', 'free', 'giveaway',
        
        # Financiero
        'dinero', 'transferencia', 'cuenta', 'banco', 'tarjeta',
        'contraseña', 'clave', 'pin', 'verificar cuenta',
        'bitcoin', 'crypto', 'inversión', 'ganancias',
        
        # Acciones requeridas
        'confirmar', 'validar', 'actualizar', 'verificar', 'clic aquí',
        'haz clic', 'pulsa aquí', 'ingresa aquí', 'únete', 'unirse',
        
        # Amenazas
        'suspendido', 'bloqueado', 'problema', 'error', 'actividad sospechosa',
        'borren', 'eliminar', 'cerrar', 
        
        # Ofertas
        'oferta limitada', 'últimas unidades', 'descuento', '100%',
        
        # Credenciales
        'username', 'password', 'user', 'pass', 'login',
        
        # Contenido adulto / Scams
        'pack', 'filtró', 'filtrado', 'privado', 'privados', 'viral',
        'videos exclusivos', 'fotos exclusivas', 'contenido exclusivo',
        'famosa', 'famoso', 'tiktoker', 'influencer', 'onlyfans',
        
        # Grupos/Canales sospechosos
        'canal', 'grupo exclusivo', 'invitación', 'link privado',
        'enlace privado', 'unirse al grupo', 'únete al canal',
        
        # Manipulación emocional
        'no te lo pierdas', 'oportunidad única', 'última oportunidad',
        'solo para ti', 'elegido', 'seleccionado',
        
        # Indicadores de scam
        '🔥', '💰', '🚀', '👇', '⚠️',  # Emojis frecuentes en scams
    ]
    
    count = sum(1 for keyword in suspicious_keywords if keyword in text_lower)
    return count


def has_excessive_caps(text: str, threshold: float = 0.6) -> bool:
    """
    Verifica si el texto tiene demasiadas mayúsculas.
    
    Args:
        text: Texto a analizar
        threshold: Porcentaje mínimo de mayúsculas (0-1)
    
    Returns:
        True si excede el threshold
    """
    if len(text) == 0:
        return False
    
    letters = [c for c in text if c.isalpha()]
    if len(letters) == 0:
        return False
    
    caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
    return caps_ratio > threshold


def has_excessive_emojis(text: str, threshold: int = 5) -> bool:
    """
    Verifica si el texto tiene demasiados emojis.
    
    Args:
        text: Texto a analizar
        threshold: Número máximo de emojis permitidos
    
    Returns:
        True si excede el threshold
    """
    # Patrón simple para detectar emojis comunes
    emoji_pattern = r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]'
    emojis = re.findall(emoji_pattern, text)
    return len(emojis) > threshold


# ==================
# Formateo
# ==================

def format_timestamp(dt: datetime) -> str:
    """Formatea un timestamp para mostrar."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def truncate_text(text: str, max_length: int = 100) -> str:
    """
    Trunca un texto si es muy largo.
    
    Args:
        text: Texto a truncar
        max_length: Longitud máxima
    
    Returns:
        Texto truncado con '...' si es necesario
    """
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


def format_threat_message(category: str, confidence: int, reasoning: str, indicators: List[str]) -> str:
    """
    Formatea un mensaje de amenaza para mostrar al usuario.
    
    Args:
        category: Categoría de la amenaza
        confidence: Nivel de confianza
        reasoning: Razonamiento
        indicators: Lista de indicadores
    
    Returns:
        Mensaje formateado
    """
    emoji_map = {
        "PHISHING": "🎣",
        "SPAM": "📧",
        "SOCIAL_ENGINEERING": "🎭",
        "SAFE": "✅"
    }
    
    # Traducción de categorías a español
    category_labels_es = {
        "PHISHING": "Phishing (Suplantación)",
        "SPAM": "Spam",
        "SOCIAL_ENGINEERING": "Ingeniería Social",
        "SAFE": "Seguro",
        "UNKNOWN": "Desconocido"
    }
    
    emoji = emoji_map.get(category, "⚠️")
    category_es = category_labels_es.get(category, category)
    
    message = f"{emoji} **{category_es}** (Certeza del análisis: {confidence}%)\n\n"
    message += f"**Análisis:** {reasoning}\n\n"
    
    if indicators:
        message += "**Indicadores detectados:**\n"
        for indicator in indicators[:5]:  # Mostrar máximo 5
            message += f"• {indicator}\n"
    
    return message


def sanitize_text(text: str) -> str:
    """
    Sanitiza texto para almacenamiento seguro.
    
    Args:
        text: Texto a sanitizar
    
    Returns:
        Texto sanitizado
    """
    # Eliminar caracteres de control
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    # Limitar longitud
    max_length = 10000
    if len(text) > max_length:
        text = text[:max_length]
    
    return text.strip()


# ==================
# Utilidades de Tiempo
# ==================

def get_time_ago(dt: datetime) -> str:
    """
    Retorna una representación legible de cuánto tiempo ha pasado.
    
    Args:
        dt: Fecha/hora a comparar
    
    Returns:
        String describiendo el tiempo transcurrido
    """
    now = datetime.utcnow()
    diff = now - dt
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "hace unos segundos"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"hace {minutes} minuto{'s' if minutes != 1 else ''}"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"hace {hours} hora{'s' if hours != 1 else ''}"
    else:
        days = int(seconds / 86400)
        return f"hace {days} día{'s' if days != 1 else ''}"


# ==================
# Análisis de Riesgo
# ==================

def calculate_risk_score(
    has_urls: bool,
    suspicious_url_count: int,
    suspicious_keyword_count: int,
    has_phone: bool,
    has_email: bool,
    has_crypto: bool,
    excessive_caps: bool,
    excessive_emojis: bool
) -> int:
    """
    Calcula un score de riesgo basándose en varios indicadores.
    Los pesos están calibrados para reflejar de forma realista el nivel
    de peligrosidad del mensaje.
    
    Returns:
        Score de 0-100
    """
    score = 0
    
    # Puntuación base si hay algún indicador sospechoso
    any_indicator = (has_urls or suspicious_url_count > 0 or 
                     suspicious_keyword_count > 0 or has_phone or 
                     has_email or has_crypto or excessive_caps or excessive_emojis)
    if any_indicator:
        score += 10  # Base mínima de riesgo
    
    # URLs (presencia de URLs ya implica riesgo moderado)
    if has_urls:
        score += 20
    # URLs sospechosas son un indicador fuerte
    score += suspicious_url_count * 30
    
    # Keywords sospechosas (cada una suma más, tope más alto)
    score += min(suspicious_keyword_count * 8, 45)
    
    # Información de contacto (posible spam/scam)
    if has_phone:
        score += 15
    if has_email:
        score += 10
    if has_crypto:
        score += 35  # Crypto = alta probabilidad de scam
    
    # Formato del mensaje (indicadores de spam/phishing)
    if excessive_caps:
        score += 20
    if excessive_emojis:
        score += 15
    
    # Limitar a 100
    return min(score, 100)
