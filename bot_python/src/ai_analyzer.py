"""
ai_analyzer.py - Analizador de IA con Ollama
Módulo principal para análisis de mensajes usando modelos de IA locales.
"""

import json
import hashlib
import logging
import asyncio
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import ollama

from config import Config
from utils import (
    extract_urls, is_suspicious_url, is_url_shortener,
    extract_phone_numbers, extract_emails, extract_crypto_addresses,
    count_suspicious_keywords, has_excessive_caps, has_excessive_emojis,
    calculate_risk_score, extract_telegram_links, has_obfuscated_urls
)

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """Clase para analizar mensajes usando Ollama."""
    
    def __init__(self):
        self.client = None
        self.model = Config.OLLAMA_MODEL
        self.cache = {} if Config.ENABLE_CACHE else None
        self._connected = False
    
    async def connect(self):
        """Inicia conexión con Ollama y descarga el modelo si es necesario."""
        try:
            logger.info(f"Conectando a Ollama: {Config.OLLAMA_HOST}")
            
            # Configurar cliente
            self.client = ollama.Client(host=Config.OLLAMA_HOST)
            
            # Verificar que el modelo está disponible
            await self._ensure_model_available()
            
            self._connected = True
            logger.info(f"Ollama conectado - Modelo: {self.model}")
            
        except Exception as e:
            logger.error(f"Error al conectar a Ollama: {e}")
            raise
    
    async def _ensure_model_available(self):
        """Verifica que el modelo esté disponible, lo descarga si es necesario."""
        try:
            # Listar modelos disponibles
            models = self.client.list()
            model_names = [model.get('model', model.get('name', '')) for model in models.get('models', [])]
            
            # Comparar ignorando el tag :latest para evitar falsos negativos
            model_base = self.model.split(':')[0]
            already_available = any(
                m == self.model or m.startswith(model_base + ':') or m == model_base
                for m in model_names
            )
            if not already_available:
                logger.info(f"Descargando modelo {self.model}... (esto puede tardar varios minutos)")
                self.client.pull(self.model)
                logger.info(f"Modelo {self.model} descargado")
            else:
                logger.info(f"Modelo {self.model} ya está disponible")
                
        except Exception as e:
            logger.error(f"Error al verificar/descargar modelo: {e}")
            raise
    
    def _get_from_cache(self, message: str) -> Optional[Dict]:
        """Obtiene resultado del caché si existe y no ha expirado."""
        if not self.cache:
            return None
        
        cache_key = hashlib.sha256(message.encode()).hexdigest()
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            
            # Verificar si el caché ha expirado
            if datetime.now() - timestamp < timedelta(seconds=Config.CACHE_TTL):
                logger.debug("Resultado obtenido del caché")
                return cached_data
            else:
                # Eliminar caché expirado
                del self.cache[cache_key]
        
        return None
    
    def _save_to_cache(self, message: str, result: Dict):
        """Guarda resultado en caché."""
        if not self.cache:
            return
        
        cache_key = hashlib.sha256(message.encode()).hexdigest()
        self.cache[cache_key] = (result, datetime.now())
        
        # Limitar tamaño del caché
        if len(self.cache) > 1000:
            # Eliminar entradas más antiguas
            oldest_keys = sorted(
                self.cache.keys(),
                key=lambda k: self.cache[k][1]
            )[:100]
            for key in oldest_keys:
                del self.cache[key]
    
    async def analyze_message(self, message: str) -> Dict[str, Any]:
        """
        Analiza un mensaje y determina si es una amenaza.
        
        Args:
            message: Texto del mensaje a analizar
        
        Returns:
            Diccionario con el análisis:
            {
                "category": "PHISHING|SPAM|SOCIAL_ENGINEERING|SAFE",
                "confidence": 0-100,
                "reasoning": "Explicación",
                "indicators": ["lista de indicadores"],
                "risk_score": 0-100,
                "metadata": {...}
            }
        """
        try:
            # Verificar caché
            cached_result = self._get_from_cache(message)
            if cached_result:
                return cached_result
            
            logger.info(f"Analizando mensaje: {message[:50]}...")
            
            # 1. Extracción de características
            features = self._extract_features(message)
            
            # 2. Análisis con IA
            ai_analysis = await self._ai_classify(message, features)
            
            # 3. Análisis heurístico
            heuristic_score = self._heuristic_analysis(features)
            
            # 4. Combinar análisis
            final_result = self._combine_analyses(ai_analysis, heuristic_score, features)
            
            # Guardar en caché
            self._save_to_cache(message, final_result)
            
            logger.info(
                f"Análisis completado: {final_result['category']} "
                f"(Confianza: {final_result['confidence']}%)"
            )
            
            return final_result
            
        except Exception as e:
            logger.error(f"Error en análisis: {e}")
            # Retornar análisis de fallback
            return self._fallback_analysis(message)
    
    def _extract_features(self, message: str) -> Dict[str, Any]:
        """Extrae características relevantes del mensaje."""
        urls = extract_urls(message)
        telegram_links = extract_telegram_links(message)
        
        features = {
            "length": len(message),
            "urls": urls,
            "url_count": len(urls),
            "suspicious_urls": [url for url in urls if is_suspicious_url(url)],
            "url_shorteners": [url for url in urls if is_url_shortener(url)],
            "telegram_links": telegram_links,
            "has_obfuscated_urls": has_obfuscated_urls(message),
            "phone_numbers": extract_phone_numbers(message),
            "emails": extract_emails(message),
            "crypto_addresses": extract_crypto_addresses(message),
            "suspicious_keyword_count": count_suspicious_keywords(message),
            "excessive_caps": has_excessive_caps(message),
            "excessive_emojis": has_excessive_emojis(message),
        }
        
        return features
    
    async def _ai_classify(self, message: str, features: Dict) -> Dict[str, Any]:
        """Utiliza IA para clasificar el mensaje."""
        try:
            # Crear prompt con contexto
            prompt = Config.ANALYSIS_PROMPT_TEMPLATE.format(message=message)
            
            # Añadir información de características extraídas
            if features['urls']:
                prompt += f"\n\nURLs detectadas: {', '.join(features['urls'][:3])}"
            if features['suspicious_keyword_count'] > 0:
                prompt += f"\nPalabras clave sospechosas encontradas: {features['suspicious_keyword_count']}"
            
            # Llamar a Ollama con timeout para no bloquear el bot indefinidamente
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self.client.chat,
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": Config.SYSTEM_PROMPT
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    format="json",
                    options={
                        "temperature": 0.3,
                        "num_predict": 200,  # Balance entre velocidad y calidad del JSON
                        "num_thread": 3,     # 3 threads, deja 1 núcleo libre para el sistema
                    }
                ),
                timeout=Config.OLLAMA_TIMEOUT
            )

            # Parsear respuesta
            content = response['message']['content']
            
            # Intentar extraer JSON de la respuesta
            ai_result = self._parse_ai_response(content)
            
            return ai_result
            
        except Exception as e:
            logger.error(f"Error en clasificación con IA: {e}")
            return {
                "category": "UNKNOWN",
                "confidence": 0,
                "reasoning": f"Error en análisis: {str(e)}",
                "indicators": []
            }
    
    def _parse_ai_response(self, content: str) -> Dict:
        """Parsea la respuesta de la IA y extrae el JSON."""
        try:
            # Buscar JSON en la respuesta
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = content[json_start:json_end]
                result = json.loads(json_str)
                
                # Validar estructura
                if all(key in result for key in ['category', 'confidence', 'reasoning']):
                    # Normalizar categoría con fuzzy matching (TinyLlama produce typos)
                    raw_cat = str(result['category']).upper()
                    if 'PHISH' in raw_cat:
                        result['category'] = 'PHISHING'
                    elif 'SOCIAL' in raw_cat or 'ENGINEERING' in raw_cat:
                        result['category'] = 'SOCIAL_ENGINEERING'
                    elif 'SPAM' in raw_cat:
                        result['category'] = 'SPAM'
                    elif 'SAFE' in raw_cat:
                        result['category'] = 'SAFE'

                    # Normalizar confidence si viene como decimal (0.95 → 95)
                    if isinstance(result['confidence'], float) and result['confidence'] <= 1.0:
                        result['confidence'] = int(result['confidence'] * 100)

                    # Extraer reasoning de list/dict si TinyLlama lo anida
                    reasoning = result['reasoning']
                    if isinstance(reasoning, list):
                        parts = []
                        for item in reasoning:
                            parts.append(item.get('text', str(item)) if isinstance(item, dict) else str(item))
                        result['reasoning'] = ' '.join(parts)
                    elif isinstance(reasoning, dict):
                        result['reasoning'] = reasoning.get('text', str(reasoning))

                    # Asegurar que indicators existe y es lista de strings
                    if 'indicators' not in result:
                        result['indicators'] = []
                    result['indicators'] = [
                        item.get('text', str(item)) if isinstance(item, dict) else str(item)
                        for item in result['indicators']
                    ]
                    return result
            
            # Si no se puede parsear JSON, intentar análisis de texto
            return self._parse_text_response(content)
            
        except json.JSONDecodeError:
            return self._parse_text_response(content)
    
    def _parse_text_response(self, content: str) -> Dict:
        """Parsea una respuesta de texto cuando no hay JSON válido."""
        content_lower = content.lower()
        
        # Determinar categoría basándose en palabras clave
        if 'phishing' in content_lower:
            category = 'PHISHING'
            confidence = 70
        elif 'spam' in content_lower:
            category = 'SPAM'
            confidence = 70
        elif 'social' in content_lower or 'engineering' in content_lower or 'ingeniería' in content_lower:
            category = 'SOCIAL_ENGINEERING'
            confidence = 70
        elif 'safe' in content_lower or 'seguro' in content_lower:
            category = 'SAFE'
            confidence = 70
        else:
            category = 'UNKNOWN'
            confidence = 50
        
        return {
            "category": category,
            "confidence": confidence,
            "reasoning": content[:200],
            "indicators": []
        }
    
    def _heuristic_analysis(self, features: Dict) -> int:
        """Realiza un análisis heurístico y retorna un score de riesgo."""
        score = calculate_risk_score(
            has_urls=features['url_count'] > 0,
            suspicious_url_count=len(features['suspicious_urls']) + len(features['url_shorteners']),
            suspicious_keyword_count=features['suspicious_keyword_count'],
            has_phone=len(features['phone_numbers']) > 0,
            has_email=len(features['emails']) > 0,
            has_crypto=len(features['crypto_addresses']) > 0,
            excessive_caps=features['excessive_caps'],
            excessive_emojis=features['excessive_emojis']
        )
        
        # Penalizar fuertemente las URLs ofuscadas (técnica de evasión)
        if features.get('has_obfuscated_urls', False):
            score += 35
        
        # Añadir riesgo por enlaces de Telegram (común en spam/scams)
        telegram_links = features.get('telegram_links', [])
        if telegram_links:
            score += min(len(telegram_links) * 20, 45)
        
        return min(score, 100)
    
    def _combine_analyses(
        self, 
        ai_analysis: Dict, 
        heuristic_score: int, 
        features: Dict
    ) -> Dict[str, Any]:
        """Combina el análisis de IA con el análisis heurístico."""
        
        # Obtener categoría de IA
        ai_category = ai_analysis.get('category', 'UNKNOWN')
        ai_confidence = ai_analysis.get('confidence', 50)
        
        # --- Calibración de confianza ---
        
        # Si la IA dice que es seguro pero el score heurístico es moderado-alto, reducir confianza
        if ai_category == 'SAFE' and heuristic_score > 40:
            ai_confidence = max(35, 100 - heuristic_score)
        
        # Si la IA detecta amenaza:
        if ai_category != 'SAFE':
            if heuristic_score > 50:
                # Evidencia heurística respalda la amenaza: incremento moderado
                ai_confidence = min(95, ai_confidence + (heuristic_score // 10))
            elif heuristic_score < 30:
                # Poca evidencia heurística: reducir confianza (la IA puede estar sobreestimando)
                ai_confidence = max(40, ai_confidence - 15)
        
        # Compilar indicadores
        indicators = list(ai_analysis.get('indicators', []))
        
        if features['suspicious_urls']:
            indicators.extend([f"URL sospechosa: {url}" for url in features['suspicious_urls'][:2]])
        
        if features['url_shorteners']:
            indicators.append("URL acortada detectada")
        
        if features.get('has_obfuscated_urls', False):
            indicators.append("⚠️ URL ofuscada detectada (técnica de evasión)")
        
        if features.get('telegram_links'):
            indicators.append(f"Enlace de Telegram: {features['telegram_links'][0]}")
        
        if features['crypto_addresses']:
            indicators.append("Dirección de criptomoneda detectada")
        
        if features['suspicious_keyword_count'] > 3:
            indicators.append(f"{features['suspicious_keyword_count']} palabras clave sospechosas")
        
        if features['excessive_caps']:
            indicators.append("Uso excesivo de mayúsculas")
        
        # --- Calcular puntuación de riesgo combinada ---
        # La puntuación de riesgo combina la evidencia heurística con la opinión de la IA
        # para que ambas métricas sean coherentes entre sí.
        if ai_category != 'SAFE':
            # Para amenazas: combinar heurísticas (40%) + confianza IA (60%)
            ai_risk_component = ai_confidence  # Si la IA está 95% segura de amenaza → alto riesgo
            combined_risk = int(heuristic_score * 0.4 + ai_risk_component * 0.6)
        else:
            # Para mensajes seguros: el riesgo es inversamente proporcional a la confianza
            ai_risk_component = max(0, 100 - ai_confidence)
            combined_risk = int(heuristic_score * 0.6 + ai_risk_component * 0.4)
        
        combined_risk = min(combined_risk, 100)
        
        # Crear resultado final
        result = {
            "category": ai_category,
            "confidence": int(ai_confidence),
            "reasoning": ai_analysis.get('reasoning', 'Sin análisis disponible'),
            "indicators": indicators,
            "risk_score": combined_risk,
            "metadata": {
                "ai_model": self.model,
                "features": features,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        return result
    
    def _fallback_analysis(self, message: str) -> Dict[str, Any]:
        """Análisis de respaldo cuando la IA falla."""
        features = self._extract_features(message)
        heuristic_score = self._heuristic_analysis(features)
        
        # Determinar categoría basándose solo en heurísticas
        if heuristic_score > 80:
            category = "PHISHING"  # Alto riesgo = probable phishing
        elif heuristic_score > 60:
            category = "SPAM"
        elif heuristic_score > 40:
            category = "SOCIAL_ENGINEERING"
        else:
            category = "SAFE"
        
        return {
            "category": category,
            "confidence": min(heuristic_score, 75),  # Máximo 75% sin IA
            "reasoning": "Análisis basado en heurísticas (IA no disponible)",
            "indicators": [],
            "risk_score": heuristic_score,
            "metadata": {
                "fallback": True,
                "features": features,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    
    def is_connected(self) -> bool:
        """Verifica si está conectado."""
        return self._connected
    
    async def health_check(self) -> bool:
        """Verifica que Ollama esté funcionando."""
        try:
            if not self.client:
                return False
            
            # Hacer una consulta simple
            response = await asyncio.to_thread(
                self.client.chat,
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                options={"num_predict": 1}
            )
            
            return True
            
        except Exception:
            return False


# Instancia global
ai_analyzer = AIAnalyzer()


# Funciones de conveniencia
async def init_ai_analyzer():
    """Inicializa el analizador de IA."""
    await ai_analyzer.connect()


if __name__ == "__main__":
    # Test del analizador
    async def test():
        await init_ai_analyzer()
        
        # Test con mensaje de phishing
        test_message = """
        ¡URGENTE! Tu cuenta bancaria ha sido suspendida.
        Haz clic aquí inmediatamente para validar tu información:
        http://banco-falso.com/login
        """
        
        result = await ai_analyzer.analyze_message(test_message)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    asyncio.run(test())
