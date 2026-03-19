"""
test_alerta_red.py - Prueba de envío de alerta de red crítica por Telegram
Ejecutar desde la carpeta bot_python/:
    python test_alerta_red.py
"""

import asyncio
import os
import sys
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from telegram import Bot
from telegram.error import TelegramError


async def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")

    if not token:
        print("ERROR: TELEGRAM_BOT_TOKEN no está configurado en .env")
        return
    if not chat_id or chat_id == "0":
        print("ERROR: TELEGRAM_CHAT_ID no está configurado en .env")
        return

    print(f"Enviando alerta de prueba al chat {chat_id}...")

    # Alerta simulada de Suricata - severidad 1 (crítica)
    alerta_simulada = {
        "severity": 1,
        "signature": "ET MALWARE Possible Botnet C2 Communication",
        "category": "Malware Command and Control Activity Detected",
        "source_ip": "192.168.1.45",
        "source_port": 54321,
        "dest_ip": "185.220.101.5",
        "dest_port": 443,
        "protocol": "TCP",
    }

    severity_emoji = ["ℹ️", "⚠️", "🚨", "🔥"][min(alerta_simulada["severity"] - 1, 3)]

    mensaje = (
        f"{severity_emoji} <b>ALERTA DE RED CRÍTICA</b>\n\n"
        f"<b>Firma:</b> {alerta_simulada['signature']}\n"
        f"<b>Categoría:</b> {alerta_simulada['category']}\n"
        f"<b>Origen:</b> {alerta_simulada['source_ip']}:{alerta_simulada['source_port']}\n"
        f"<b>Destino:</b> {alerta_simulada['dest_ip']}:{alerta_simulada['dest_port']}\n"
        f"<b>Protocolo:</b> {alerta_simulada['protocol']}\n\n"
        f"<i>(Esto es un mensaje de prueba)</i>"
    )

    try:
        bot = Bot(token=token)
        await bot.send_message(chat_id=int(chat_id), text=mensaje, parse_mode="HTML")
        print("[OK] Alerta enviada correctamente. Comprueba tu Telegram.")
    except TelegramError as e:
        print(f"[ERROR] Error de Telegram: {e}")
        if "chat not found" in str(e).lower():
            print("   -> El chat ID es incorrecto o el bot no esta en ese chat.")
            print("   -> Envia primero un mensaje al bot para que te pueda escribir.")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    asyncio.run(main())
