"""
test_messages.py - Suite de pruebas para el sistema de clasificación de amenazas
Prueba la detección de phishing, spam y ingeniería social
"""

import asyncio
import sys
import os

# Añadir el directorio src al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ai_analyzer import ai_analyzer
from threat_classifier import threat_classifier
from database import db
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ========================================
# Mensajes de Prueba
# ========================================

# Casos de PHISHING
PHISHING_MESSAGES = [
    {
        "text": """¡URGENTE! Tu cuenta bancaria ha sido suspendida por actividad sospechosa.
        Haz clic aquí para verificar tu identidad inmediatamente:
        http://banco-seguridad-falso.com/login.php
        Si no confirmas en 24 horas, tu cuenta será bloqueada permanentemente.""",
        "expected": "PHISHING",
        "description": "Phishing bancario clásico"
    },
    {
        "text": """Netflix: Tu suscripción ha expirado. Actualiza tu información de pago aquí:
        http://netflix-payment-update.tk/verify
        Usuario: tu_email@example.com
        Contraseña: __________""",
        "expected": "PHISHING",
        "description": "Phishing de Netflix"
    },
    {
        "text": """¡Felicidades! Has ganado un iPhone 15 Pro gratis.
        Para reclamarlo, ingresa tus datos en: http://premio-iphone.ml/claim
        Necesitamos tu nombre completo, dirección y número de tarjeta para el envío.""",
        "expected": "PHISHING",
        "description": "Phishing con premio falso"
    }
]

# Casos de SPAM
SPAM_MESSAGES = [
    {
        "text": """🎉🎉🎉 ¡OFERTA INCREÍBLE! 🎉🎉🎉
        ¡DESCUENTO DEL 90% EN TODOS LOS PRODUCTOS!
        ¡SOLO POR HOY! ¡ÚLTIMAS UNIDADES!
        Llama ya al 555-1234 o visita www.oferta-increible.com
        NO DEJES PASAR ESTA OPORTUNIDAD""",
        "expected": "SPAM",
        "description": "Spam comercial con emojis excesivos"
    },
    {
        "text": """💰💰💰 GANA DINERO DESDE CASA 💰💰💰
        Trabaja solo 2 horas al día y gana $5000 al mes
        Sin experiencia necesaria
        Únete a nuestro equipo: WhatsApp 555-9876
        Oportunidad de negocio real - No es multinivel""",
        "expected": "SPAM",
        "description": "Spam de oportunidad de negocio"
    },
    {
        "text": """Hola! Te envío mi número de criptomoneda para que me hagas la transferencia:
        bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
        Es urgente, necesito el dinero hoy. Gracias!""",
        "expected": "SPAM",
        "description": "Spam con dirección de criptomoneda"
    }
]

# Casos de INGENIERÍA SOCIAL
SOCIAL_ENGINEERING_MESSAGES = [
    {
        "text": """Hola, soy el hijo de tu jefe. Necesito ayuda urgente.
        Mi padre está en el hospital y necesito que me transfieras dinero para pagar los medicamentos.
        Por favor, no le digas nada a él todavía, no quiero preocuparlo más.
        ¿Puedes ayudarme? Es muy urgente.""",
        "expected": "SOCIAL_ENGINEERING",
        "description": "Ingeniería social con apelación emocional"
    },
    {
        "text": """Departamento de Soporte Técnico: Hemos detectado un virus en tu computadora.
        Necesitamos acceso remoto AHORA para eliminarlo antes de que se pierdan todos tus archivos.
        Descarga este programa: http://soporte-tecnico-urgente.com/teamviewer.exe
        Si no actúas en los próximos 30 minutos, perderás toda tu información.""",
        "expected": "SOCIAL_ENGINEERING",
        "description": "Ingeniería social con táctica de miedo"
    },
    {
        "text": """Hola! Soy del banco. Necesito que me confirmes algunos datos para procesar tu solicitud de préstamo.
        ¿Cuál es tu número de cuenta completo y tu fecha de nacimiento?
        Es solo para verificación, no te preocupes.""",
        "expected": "SOCIAL_ENGINEERING",
        "description": "Pretexting - solicitud de información personal"
    }
]

# Casos SEGUROS
SAFE_MESSAGES = [
    {
        "text": "Hola, ¿cómo estás? ¿Nos vemos mañana para tomar un café?",
        "expected": "SAFE",
        "description": "Mensaje casual seguro"
    },
    {
        "text": """Resumen de la reunión de hoy:
        - Proyecto A: en progreso, entrega el viernes
        - Proyecto B: revisión pendiente
        - Próxima reunión: lunes 10am
        
        Saludos!""",
        "expected": "SAFE",
        "description": "Mensaje profesional seguro"
    },
    {
        "text": "Gracias por tu ayuda con el código. Ya funciona perfecto!",
        "expected": "SAFE",
        "description": "Mensaje de agradecimiento"
    }
]


class TestResults:
    """Clase para almacenar y mostrar resultados de pruebas."""
    
    def __init__(self):
        self.total = 0
        self.correct = 0
        self.incorrect = 0
        self.details = []
    
    def add_result(self, expected: str, actual: str, message: str, description: str, confidence: int):
        self.total += 1
        correct = (expected == actual)
        
        if correct:
            self.correct += 1
        else:
            self.incorrect += 1
        
        self.details.append({
            "expected": expected,
            "actual": actual,
            "correct": correct,
            "message": message[:80],
            "description": description,
            "confidence": confidence
        })
    
    def print_summary(self):
        """Imprime resumen de resultados."""
        print("\n" + "="*80)
        print("RESUMEN DE PRUEBAS")
        print("="*80)
        print(f"Total de pruebas: {self.total}")
        print(f"✅ Correctas: {self.correct} ({self.correct/self.total*100:.1f}%)")
        print(f"❌ Incorrectas: {self.incorrect} ({self.incorrect/self.total*100:.1f}%)")
        print("="*80)
        
        if self.incorrect > 0:
            print("\n❌ PRUEBAS FALLIDAS:")
            for detail in self.details:
                if not detail["correct"]:
                    print(f"\n  Descripción: {detail['description']}")
                    print(f"  Esperado: {detail['expected']}")
                    print(f"  Obtenido: {detail['actual']} (Confianza: {detail['confidence']}%)")
                    print(f"  Mensaje: {detail['message']}...")


async def test_category(category_name: str, test_messages: list, results: TestResults):
    """Prueba una categoría específica de mensajes."""
    print(f"\n{'='*80}")
    print(f"Probando categoría: {category_name}")
    print(f"{'='*80}\n")
    
    for i, test_case in enumerate(test_messages, 1):
        message = test_case["text"]
        expected = test_case["expected"]
        description = test_case["description"]
        
        print(f"[{i}/{len(test_messages)}] {description}")
        print(f"  Mensaje: {message[:80]}...")
        
        # Analizar mensaje
        result = await ai_analyzer.analyze_message(message)
        
        actual = result["category"]
        confidence = result["confidence"]
        
        # Verificar resultado
        is_correct = (actual == expected)
        emoji = "✅" if is_correct else "❌"
        
        print(f"  {emoji} Esperado: {expected} | Obtenido: {actual} (Confianza: {confidence}%)")
        
        if result["indicators"]:
            print(f"  Indicadores: {', '.join(result['indicators'][:3])}")
        
        results.add_result(expected, actual, message, description, confidence)
        print()


async def run_all_tests():
    """Ejecuta todas las pruebas."""
    print("="*80)
    print("🧪 SISTEMA DE PRUEBAS - Clasificación de Amenazas")
    print("="*80)
    
    # Inicializar sistema
    print("\n🔧 Inicializando sistema...")
    await ai_analyzer.connect()
    print("✅ Sistema inicializado\n")
    
    results = TestResults()
    
    # Ejecutar pruebas por categoría
    await test_category("PHISHING", PHISHING_MESSAGES, results)
    await test_category("SPAM", SPAM_MESSAGES, results)
    await test_category("INGENIERÍA SOCIAL", SOCIAL_ENGINEERING_MESSAGES, results)
    await test_category("MENSAJES SEGUROS", SAFE_MESSAGES, results)
    
    # Mostrar resumen
    results.print_summary()
    
    # Guardar resultados si hay DB
    try:
        if db.is_connected():
            print("\n💾 Guardando resultados en base de datos...")
            for detail in results.details:
                await db.save_message({
                    "text": detail["message"],
                    "category": detail["actual"],
                    "expected_category": detail["expected"],
                    "confidence": detail["confidence"],
                    "correct": detail["correct"],
                    "test_description": detail["description"],
                    "is_test": True
                })
            print("✅ Resultados guardados")
    except Exception as e:
        print(f"⚠️  No se pudieron guardar los resultados: {e}")
    
    # Retornar código de salida basado en resultados
    return 0 if results.incorrect == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
