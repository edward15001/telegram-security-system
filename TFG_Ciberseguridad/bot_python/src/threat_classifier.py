"""
threat_classifier.py - Clasificador especializado de amenazas
Módulo con lógica específica para cada tipo de amenaza.
"""

import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ThreatPattern:
    """Patrón de amenaza detectado."""
    type: str
    confidence: int
    description: str
    indicators: List[str]


class ThreatClassifier:
    """Clasificador especializado en tipos de amenazas."""
    
    # Patrones de phishing
    PHISHING_PATTERNS = {
        "credential_harvest": {
            "keywords": ["contraseña", "password", "clave", "pin", "verificar", "validar", "confirmar cuenta"],
            "weight": 30
        },
        "urgency": {
            "keywords": ["urgente", "inmediato", "ahora mismo", "suspendida", "bloqueada", "último día"],
            "weight": 20
        },
        "impersonation": {
            "keywords": ["banco", "paypal", "netflix", "amazon", "google", "facebook", "whatsapp"],
            "weight": 25
        },
        "action_required": {
            "keywords": ["haz clic", "pulsa aquí", "ingresa aquí", "actualiza tus datos", "confirma tu identidad"],
            "weight": 20
        }
    }
    
    # Patrones de spam
    SPAM_PATTERNS = {
        "commercial": {
            "keywords": ["oferta", "descuento", "gratis", "promoción", "compra ahora", "oferta limitada"],
            "weight": 25
        },
        "prizes": {
            "keywords": ["ganador", "premio", "sorteo", "lotería", "has ganado", "felicidades ganaste"],
            "weight": 30
        },
        "mlm": {
            "keywords": ["ganar dinero", "trabaja desde casa", "ingresos pasivos", "multinivel", "oportunidad de negocio"],
            "weight": 25
        },
        "unsolicited": {
            "keywords": ["promoción exclusiva", "solo por hoy", "últimas unidades", "no lo pierdas"],
            "weight": 15
        }
    }
    
    # Patrones de ingeniería social
    SOCIAL_ENGINEERING_PATTERNS = {
        "pretexting": {
            "keywords": ["necesito tu ayuda", "es urgente", "por favor ayúdame", "problema familiar"],
            "weight": 25
        },
        "baiting": {
            "keywords": ["descarga gratis", "regalo para ti", "contenido exclusivo", "acceso premium gratis"],
            "weight": 20
        },
        "quid_pro_quo": {
            "keywords": ["a cambio de", "si me ayudas", "necesito un favor", "te pagaré"],
            "weight": 25
        },
        "fear_tactics": {
            "keywords": ["problema grave", "consecuencias", "acción legal", "policía", "demanda"],
            "weight": 30
        }
    }
    
    def __init__(self):
        pass
    
    def classify_phishing(self, message: str, features: Dict) -> Tuple[int, List[str]]:
        """
        Clasifica si el mensaje es phishing.
        
        Args:
            message: Texto del mensaje
            features: Características extraídas
        
        Returns:
            Tupla con (score 0-100, lista de indicadores)
        """
        message_lower = message.lower()
        score = 0
        indicators = []
        
        # Verificar patrones de phishing
        for pattern_name, pattern_data in self.PHISHING_PATTERNS.items():
            matches = [kw for kw in pattern_data['keywords'] if kw in message_lower]
            if matches:
                score += pattern_data['weight']
                indicators.append(f"Patrón de {pattern_name}: {', '.join(matches[:2])}")
        
        # URLs sospechosas incrementan mucho el score
        if features.get('suspicious_urls'):
            score += 40
            indicators.append(f"URL sospechosa detectada")
        
        # URLs acortadas
        if features.get('url_shorteners'):
            score += 20
            indicators.append("URL acortada (posible ocultación)")
        
        # Solicitud de credenciales + URL = muy sospechoso
        credential_keywords = ["contraseña", "password", "clave", "pin", "login"]
        has_credentials = any(kw in message_lower for kw in credential_keywords)
        if has_credentials and features.get('urls'):
            score += 30
            indicators.append("Solicitud de credenciales con enlace")
        
        return min(score, 100), indicators
    
    def classify_spam(self, message: str, features: Dict) -> Tuple[int, List[str]]:
        """
        Clasifica si el mensaje es spam.
        
        Args:
            message: Texto del mensaje
            features: Características extraídas
        
        Returns:
            Tupla con (score 0-100, lista de indicadores)
        """
        message_lower = message.lower()
        score = 0
        indicators = []
        
        # Verificar patrones de spam
        for pattern_name, pattern_data in self.SPAM_PATTERNS.items():
            matches = [kw for kw in pattern_data['keywords'] if kw in message_lower]
            if matches:
                score += pattern_data['weight']
                indicators.append(f"Patrón de {pattern_name}")
        
        # Múltiples emojis
        if features.get('excessive_emojis'):
            score += 15
            indicators.append("Uso excesivo de emojis")
        
        # Mayúsculas excesivas
        if features.get('excessive_caps'):
            score += 15
            indicators.append("TEXTO EN MAYÚSCULAS")
        
        # Teléfonos
        if features.get('phone_numbers'):
            score += 20
            indicators.append(f"Número de teléfono: {features['phone_numbers'][0]}")
        
        # Direcciones de criptomonedas (común en spam cripto)
        if features.get('crypto_addresses'):
            score += 25
            indicators.append("Dirección de criptomoneda")
        
        # Mensaje muy largo (común en spam)
        if features.get('length', 0) > 500:
            score += 10
            indicators.append("Mensaje muy extenso")
        
        return min(score, 100), indicators
    
    def classify_social_engineering(self, message: str, features: Dict) -> Tuple[int, List[str]]:
        """
        Clasifica si el mensaje usa ingeniería social.
        
        Args:
            message: Texto del mensaje
            features: Características extraídas
        
        Returns:
            Tupla con (score 0-100, lista de indicadores)
        """
        message_lower = message.lower()
        score = 0
        indicators = []
        
        # Verificar patrones de ingeniería social
        for pattern_name, pattern_data in self.SOCIAL_ENGINEERING_PATTERNS.items():
            matches = [kw for kw in pattern_data['keywords'] if kw in message_lower]
            if matches:
                score += pattern_data['weight']
                indicators.append(f"Táctica de {pattern_name}")
        
        # Apelaciones emocionales
        emotional_keywords = [
            "por favor", "ayuda", "urgente", "desesperado", "familia",
            "enfermo", "hospital", "problema grave", "necesito"
        ]
        emotional_count = sum(1 for kw in emotional_keywords if kw in message_lower)
        if emotional_count > 2:
            score += 20
            indicators.append("Apelación emocional fuerte")
        
        # Solicitud de información personal
        personal_info_keywords = [
            "número de cuenta", "tarjeta", "cvv", "fecha de nacimiento",
            "dirección", "dni", "documento", "cédula"
        ]
        if any(kw in message_lower for kw in personal_info_keywords):
            score += 30
            indicators.append("Solicitud de información personal")
        
        # Promesas de dinero
        money_keywords = ["dinero fácil", "ganar dinero", "transferencia", "enviar dinero"]
        if any(kw in message_lower for kw in money_keywords):
            score += 25
            indicators.append("Promesas monetarias")
        
        return min(score, 100), indicators
    
    def classify(self, message: str, features: Dict) -> Dict[str, ThreatPattern]:
        """
        Clasifica el mensaje para todos los tipos de amenazas.
        
        Args:
            message: Texto del mensaje
            features: Características extraídas
        
        Returns:
            Diccionario con patrones detectados por tipo
        """
        results = {}
        
        # Clasificar phishing
        phishing_score, phishing_indicators = self.classify_phishing(message, features)
        if phishing_score > 0:
            results['PHISHING'] = ThreatPattern(
                type='PHISHING',
                confidence=phishing_score,
                description='Posible intento de obtener credenciales o información sensible',
                indicators=phishing_indicators
            )
        
        # Clasificar spam
        spam_score, spam_indicators = self.classify_spam(message, features)
        if spam_score > 0:
            results['SPAM'] = ThreatPattern(
                type='SPAM',
                confidence=spam_score,
                description='Mensaje comercial no solicitado o repetitivo',
                indicators=spam_indicators
            )
        
        # Clasificar ingeniería social
        social_score, social_indicators = self.classify_social_engineering(message, features)
        if social_score > 0:
            results['SOCIAL_ENGINEERING'] = ThreatPattern(
                type='SOCIAL_ENGINEERING',
                confidence=social_score,
                description='Manipulación psicológica para obtener información o acciones',
                indicators=social_indicators
            )
        
        return results
    
    def get_primary_threat(self, classifications: Dict[str, ThreatPattern]) -> ThreatPattern:
        """
        Obtiene la amenaza principal basándose en el score más alto.
        
        Args:
            classifications: Diccionario de clasificaciones
        
        Returns:
            Patrón de amenaza con mayor confianza
        """
        if not classifications:
            return ThreatPattern(
                type='SAFE',
                confidence=100,
                description='No se detectaron amenazas',
                indicators=[]
            )
        
        # Obtener la amenaza con mayor confianza
        primary = max(classifications.values(), key=lambda x: x.confidence)
        return primary


# Instancia global
threat_classifier = ThreatClassifier()


if __name__ == "__main__":
    # Test del clasificador
    test_messages = [
        {
            "text": "¡URGENTE! Tu cuenta ha sido suspendida. Verifica tu contraseña aquí: http://fake-bank.com",
            "type": "phishing"
        },
        {
            "text": "🎉🎉🎉 ¡FELICIDADES! Has ganado un iPhone 15 GRATIS. Llama ya al 555-1234",
            "type": "spam"
        },
        {
            "text": "Hola, necesito tu ayuda urgente. Es un problema familiar grave. ¿Puedes enviarme dinero?",
            "type": "social engineering"
        }
    ]
    
    for test in test_messages:
        print(f"\n{'='*60}")
        print(f"Mensaje: {test['text']}")
        print(f"Tipo esperado: {test['type']}")
        print('='*60)
        
        # Simular features básicas
        features = {
            "urls": ["http://fake-bank.com"] if "http" in test['text'] else [],
            "suspicious_urls": ["http://fake-bank.com"] if "fake-bank" in test['text'] else [],
            "url_shorteners": [],
            "phone_numbers": ["555-1234"] if "555-1234" in test['text'] else [],
            "crypto_addresses": [],
            "excessive_emojis": test['text'].count('🎉') > 3,
            "excessive_caps": sum(1 for c in test['text'] if c.isupper()) / max(len(test['text']), 1) > 0.3,
            "length": len(test['text'])
        }
        
        classifications = threat_classifier.classify(test['text'], features)
        
        for threat_type, pattern in classifications.items():
            print(f"\n{threat_type}: {pattern.confidence}%")
            print(f"Descripción: {pattern.description}")
            print(f"Indicadores: {', '.join(pattern.indicators)}")
        
        primary = threat_classifier.get_primary_threat(classifications)
        print(f"\n⚠️ AMENAZA PRINCIPAL: {primary.type} ({primary.confidence}%)")
