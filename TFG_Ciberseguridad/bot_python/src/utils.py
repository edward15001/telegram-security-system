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

def extract_urls(text: str) -> List[str]:
    """
    Extrae todas las URLs de un texto.
    
    Args:
        text: Texto del que extraer URLs
    
    Returns:
        Lista de URLs encontradas
    """
    # Patrón para detectar URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    
    # También buscar URLs sin protocolo
    no_protocol_pattern = r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls_no_protocol = re.findall(no_protocol_pattern, text)
    urls.extend(['http://' + url for url in urls_no_protocol])
    
    return list(set(urls))  # Eliminar duplicados


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
        
        # Premios/Sorteos
        'ganador', 'premio', 'gratis', 'regalo', 'sorteo', 'lotería',
        
        # Financiero
        'dinero', 'transferencia', 'cuenta', 'banco', 'tarjeta',
        'contraseña', 'clave', 'pin', 'verificar cuenta',
        
        # Acciones requeridas
        'confirmar', 'validar', 'actualizar', 'verificar', 'clic aquí',
        'haz clic', 'pulsa aquí', 'ingresa aquí',
        
        # Amenazas
        'suspendido', 'bloqueado', 'problema', 'error', 'actividad sospechosa',
        
        # Ofertas
        'oferta limitada', 'últimas unidades', 'descuento', '100%',
        
        # Credenciales
        'username', 'password', 'user', 'pass', 'login',
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
    
    emoji = emoji_map.get(category, "⚠️")
    
    message = f"{emoji} **{category}** (Confianza: {confidence}%)\n\n"
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
    
    Returns:
        Score de 0-100
    """
    score = 0
    
    # URLs
    if has_urls:
        score += 10
    score += suspicious_url_count * 20
    
    # Keywords sospechosas
    score += min(suspicious_keyword_count * 5, 30)
    
    # Información de contacto (posible spam)
    if has_phone:
        score += 10
    if has_email:
        score += 5
    if has_crypto:
        score += 25
    
    # Formato del mensaje
    if excessive_caps:
        score += 15
    if excessive_emojis:
        score += 10
    
    # Limitar a 100
    return min(score, 100)
