#!/usr/bin/env python3
"""
Script de prueba para el analizador de IA
"""
import sys
sys.path.insert(0, '/app/src')

import asyncio
import logging

logging.basicConfig(level=logging.INFO)

async def main():
    from ai_analyzer import ai_analyzer
    
    print("Conectando a Ollama...")
    await ai_analyzer.connect()
    print("Conectado!")
    
    mensaje_prueba = """LA PRÓXIMA GEMAS 1000x ESTÁ AQUÍ! 🚀🚀 No te pierdas la preventa de $SCAMCOIN. Listada en Binance mañana. ✅ Liquidez bloqueada ✅ Equipo doxxed Compra ahora antes de que suba: t.me/fake_crypto_group_link"""
    
    print("\nAnalizando mensaje...")
    print(f"Mensaje: {mensaje_prueba[:80]}...")
    
    try:
        resultado = await ai_analyzer.analyze_message(mensaje_prueba)
        print("\n=== RESULTADO ===")
        print(f"Categoría: {resultado['category']}")
        print(f"Confianza: {resultado['confidence']}%")
        print(f"Razonamiento: {resultado['reasoning']}")
        print(f"Indicadores: {resultado['indicators']}")
        print(f"Risk Score: {resultado['risk_score']}")
    except Exception as e:
        print(f"\n=== ERROR ===")
        print(f"Tipo: {type(e).__name__}")
        print(f"Mensaje: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
