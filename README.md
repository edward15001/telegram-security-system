# Sistema de Ciberseguridad Inteligente en Telegram

Sistema completo de detección y clasificación de amenazas en mensajes de Telegram usando análisis de IA local con Ollama, monitoreo de red con Suricata IDS, y almacenamiento en MongoDB. Optimizado para ejecutarse en Raspberry Pi 5.

## Descripción

Este sistema analiza mensajes de Telegram en tiempo real para detectar:
- Phishing: Intentos de robo de credenciales o información sensible
- Spam: Mensajes comerciales no solicitados y contenido repetitivo
- Ingeniería Social: Manipulación psicológica para obtener información o acciones

Además, monitorea el tráfico de red relacionado con Telegram usando Suricata IDS para detectar patrones de ataque y actividad maliciosa.

## Arquitectura

El sistema está compuesto por varios servicios en Docker:

```
┌─────────────────────────────────────────────────────┐
│                  Raspberry Pi 5                      │
├─────────────────────────────────────────────────────┤
│                                                       │
│  ┌──────────────┐    ┌──────────────┐               │
│  │   Suricata   │───▶│  Monitor de  │               │
│  │     IDS      │    │     Red      │               │
│  └──────────────┘    └──────┬───────┘               │
│                              │                        │
│  ┌──────────────┐           │                        │
│  │   Telegram   │───┐       │                        │
│  │     Bot      │   │       │                        │
│  └──────────────┘   │       │                        │
│                      ▼       ▼                        │
│              ┌──────────────────┐                    │
│              │   AI Analyzer    │                    │
│              │    (Ollama)      │                    │
│              └────────┬─────────┘                    │
│                       │                              │
│                       ▼                              │
│              ┌──────────────────┐                    │
│              │     MongoDB      │                    │
│              │  (Almacenamiento)│                    │
│              └──────────────────┘                    │
└─────────────────────────────────────────────────────┘
```

## Características

- Análisis de mensajes con IA local (sin enviar datos a servicios externos)
- Clasificación multi-nivel: Phishing, Spam, Ingeniería Social
- Detección basada en patrones y análisis semántico
- Monitoreo de tráfico de red con Suricata
- Almacenamiento persistente en MongoDB
- Bot de Telegram interactivo con comandos
- Sistema de puntuación de riesgo
- Caché de resultados para optimizar rendimiento
- Logs estructurados y estadísticas en tiempo real

## Requisitos

### Hardware
- **Raspberry Pi 5** (recomendado con 8GB+ de RAM, soporta hasta 16GB)
- Tarjeta SD de al menos 32GB
- Conexión a internet

### Software
- Docker y Docker Compose
- Python 3.11+
- Git

## Instalación

### 1. Clonar el Repositorio

```bash
git clone https://github.com/edward15001/Sistema_de_Ciberseguridad_Inteligente_en_Telegram.git
cd Sistema_de_Ciberseguridad_Inteligente_en_Telegram/TFG_Ciberseguridad
```

### 2. Configurar Variables de Entorno

Copia el archivo de ejemplo y edítalo con tus credenciales:

```bash
cp .env.example .env
nano .env
```

Configura las siguientes variables:

```bash
# Token del bot de Telegram (obtener de @BotFather)
TELEGRAM_BOT_TOKEN=7646078215:TOKEN_ELIMINADO_HISTORIAL

# Configuración de Ollama
OLLAMA_MODEL=mistral:7b-instruct  # o llama2:13b, phi:latest

# Configuración de amenazas
THREAT_THRESHOLD=70

# Nivel de logging
LOG_LEVEL=INFO
```

### 3. Crear Bot de Telegram

1. Abre Telegram y busca **@BotFather**
2. Envía el comando `/newbot`
3. Sigue las instrucciones y copia el token
4. Pégalo en el archivo `.env` en `TELEGRAM_BOT_TOKEN`

### 4. Configurar Suricata (Opcional)

Edita `suricata/suricata.yaml` si necesitas ajustar:
- Interfaz de red a monitorear
- Límites de memoria
- Reglas personalizadas

### 5. Construir e Iniciar los Servicios

```bash
# Construir imágenes
docker-compose build

# Iniciar servicios
docker-compose up -d

# Ver logs
docker-compose logs -f
```

### 6. Descargar Modelo de Ollama (Primera Vez)

El modelo de IA se descargará automáticamente al iniciar. Para hacerlo manualmente:

```bash
docker-compose exec ollama ollama pull mistral:7b-instruct
```

**Nota**: La descarga del modelo puede tardar varios minutos dependiendo de tu conexión.

## Uso

### Interactuar con el Bot

1. Abre Telegram y busca tu bot usando el nombre que le diste
2. Envía `/start` para comenzar
3. Envía cualquier mensaje para analizarlo

### Comandos Disponibles

- `/start` - Mensaje de bienvenida
- `/help` - Ayuda completa
- `/alertas [cantidad]` - Ver últimas amenazas detectadas
- `/estado` - Estado de servicios del sistema
- `/stats` - Estadísticas de análisis
- `/analizar <texto>` - Analizar un mensaje específico
- `/recientes [tipo]` - Ver mensajes recientes analizados

### Análisis Automático

Simplemente envía cualquier mensaje al bot y recibirás:
- Categoría de amenaza (PHISHING, SPAM, SOCIAL_ENGINEERING, SAFE)
- Nivel de confianza (0-100%)
- Score de riesgo
- Análisis detallado
- Indicadores detectados
- Recomendaciones

## Testing

Ejecutar la suite de pruebas:

```bash
docker-compose exec bot_python python tests/test_messages.py
```

Esto probará la detección de:
- Mensajes de phishing
- Spam comercial
- Ingeniería social
- Mensajes seguros

## Probar el Sistema de Detección

Para verificar que el bot detector funciona correctamente, envía mensajes de prueba manualmente en el grupo.

### Ejemplos de Mensajes para Probar

#### SPAM
```
🎉 ¡FELICIDADES! Has ganado un iPhone 15 Pro Max GRATIS!
💰 GANA DINERO FÁCIL desde casa! $5000 al día!
📢 OFERTA LIMITADA: 90% de descuento en productos Apple!
```

#### PHISHING
```
⚠️ ALERTA BANCARIA: Tu cuenta ha sido suspendida. Verifica aquí: bit.ly/banco
🔐 SEGURIDAD TELEGRAM: Inicia sesión nuevamente: t.me/seguridad
🏦 BBVA: Confirme sus datos para evitar el cierre de cuenta
```

#### INGENIERÍA SOCIAL
```
👮 POLICÍA NACIONAL: Tiene una multa pendiente de 300€
😢 Hola, soy tu primo Carlos, tuve un accidente y necesito dinero urgente
📞 Soporte técnico Microsoft: Su PC tiene un virus, llame al +34-XXX
```

### Verificar la Detección

Cuando envíes un mensaje de prueba en el grupo, el bot detector:

1. **Recibirá el mensaje** automáticamente
2. **Lo analizará** con IA (usando Ollama + Mistral)
3. **Clasificará** el mensaje (SPAM, PHISHING, SOCIAL_ENGINEERING, o SAFE)
4. **Responderá** con un análisis detallado:
   ```
   🎣 Análisis Completado

   Categoría: PHISHING
   Confianza: 95%
   Score de Riesgo: 87/100

   Análisis:
   Mensaje sospechoso que intenta obtener credenciales...

   Indicadores Detectados:
   • URL acortada sospechosa
   • Urgencia artificial
   • Solicitud de datos sensibles

   Recomendación: Procede con precaución.
   ```
5. **Almacenará** el resultado en MongoDB

### Comandos Útiles para Testing

En el grupo, envía:

- `/stats` - Ver estadísticas de detección
- `/alertas 10` - Ver últimas 10 amenazas detectadas
- `/estado` - Ver estado del sistema
- `/recientes` - Ver mensajes recientes analizados


## Monitoreo

### Ver Estado del Sistema

```bash
# Ver todos los servicios
docker-compose ps

# Ver logs en tiempo real
docker-compose logs -f

# Ver logs de un servicio específico
docker-compose logs -f bot_python
docker-compose logs -f suricata
docker-compose logs -f ollama
docker-compose logs -f mongodb
```

### Acceder a MongoDB

```bash
# Conectar a MongoDB
docker-compose exec mongodb mongosh

# Ver base de datos
use ciberseguridad
db.messages.find().pretty()
db.alerts.find().pretty()
```

### Ver Alertas de Suricata

```bash
# Ver últimas alertas
docker-compose exec suricata tail -f /var/log/suricata/fast.log

# Ver eve.json (formato JSON)
docker-compose exec suricata tail -f /var/log/suricata/eve.json | jq
```

## Mantenimiento

### Detener el Sistema

```bash
docker-compose down
```

### Reiniciar un Servicio

```bash
docker-compose restart bot_python
```

### Limpiar Logs

```bash
# Limpiar logs de Suricata
docker-compose exec suricata rm -rf /var/log/suricata/*

# Limpiar base de datos (¡CUIDADO!)
docker-compose exec mongodb mongosh ciberseguridad --eval "db.dropDatabase()"
```

### Actualizar el Sistema

```bash
git pull
docker-compose build
docker-compose up -d
```

## Rendimiento en Raspberry Pi 5

Configuración optimizada para:
- **CPU**: 4 cores aprovechados con threading
- **RAM**: Límites configurados por servicio (16GB total)
  - Ollama: 8GB
  - Suricata: 2GB
  - MongoDB: 1GB
  - Bot Python: 2GB
- **Almacenamiento**: Logs rotados automáticamente

### Monitorear Recursos

```bash
# Ver uso de recursos
docker stats

# Ver uso de CPU/RAM del sistema
htop
```

## Seguridad

- No se envían datos a servicios externos
- Modelo de IA ejecutado localmente
- Tráfico cifrado con TLS
- Base de datos sin contraseña (solo acceso local)
- **Importante**: Mantén tu `.env` seguro y nunca lo subas a git

## Troubleshooting

### El bot no responde

```bash
# Verificar que el bot esté corriendo
docker-compose logs bot_python

# Verificar token de Telegram
docker-compose exec bot_python printenv TELEGRAM_BOT_TOKEN
```

### Ollama no carga el modelo

```bash
# Verificar modelos disponibles
docker-compose exec ollama ollama list

# Descargar modelo manualmente
docker-compose exec ollama ollama pull mistral:7b-instruct

# Ver logs de Ollama
docker-compose logs ollama
```

### Suricata no captura tráfico

```bash
# Verificar interfaz de red
ip addr

# Editar suricata.yaml con la interfaz correcta
nano suricata/suricata.yaml
# Cambiar "interface: eth0" por tu interfaz

# Reiniciar Suricata
docker-compose restart suricata
```

### MongoDB no conecta

```bash
# Verificar que MongoDB esté corriendo
docker-compose logs mongodb

# Reiniciar MongoDB
docker-compose restart mongodb
```

## Licencia

Este proyecto es parte de un Trabajo Fin de Grado de Ingeniería de Computadores.

## Autor

**Edward** - Estudiante de Ingeniería de Computadores

## Agradecimientos

- [Ollama](https://ollama.ai/) - Motor de IA local
- [Suricata](https://suricata.io/) - Sistema de detección de intrusiones
- [python-telegram-bot](https://python-telegram-bot.org/) - Librería para bots de Telegram
- [MongoDB](https://www.mongodb.com/) - Base de datos

---

**¡Sistema listo para detectar amenazas en Telegram!** 
