"""Redacción de secretos en textos que se registran o se guardan (S-01, S-02).

Una excepción de ``requests`` arrastra la URL completa: ``/bot<token>/`` en
Telegram y ``/api/webhooks/<id>/<token>`` en Discord. Aquí se tapan esos
patrones y, además, los valores exactos de las variables de canal configuradas,
antes de que el texto llegue al log, a ``notification_queue.last_error``, a
``/health`` o a ``var/alerts.log``.
"""
from __future__ import annotations

import os
import re

MARCA = "<redactado>"

# Token de bot de Telegram: <6+ dígitos>:<30+ caracteres de base64url>.
_TOKEN_TELEGRAM = re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{25,}\b")
# Webhook de Discord, con o sin dominio de pruebas.
_WEBHOOK_DISCORD = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/"
    r"\d+/[A-Za-z0-9_\-]+"
)
# Resto de la ruta del bot: /bot<token>/sendMessage entero.
_RUTA_BOT = re.compile(r"/bot[^\s'\"<>]*")

# Variables de entorno que pueden llevar un secreto de canal.
VARIABLES_DE_CANAL = ("TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "DISCORD_WEBHOOK")


def secretos_conocidos() -> tuple[str, ...]:
    """Valores no vacíos de las variables de canal del proceso."""
    valores = (os.environ.get(nombre, "") for nombre in VARIABLES_DE_CANAL)
    return tuple(valor for valor in valores if len(valor) >= 8)


def redactar(texto: object, secretos: tuple[str, ...] | None = None) -> str:
    """Devuelve ``texto`` sin tokens de Telegram, webhooks de Discord ni secretos.

    ``secretos`` permite fijar la lista (útil en tests y en el filtro de
    logging, que la calcula una vez); si es ``None`` se leen del entorno.
    """
    salida = str(texto)
    for valor in (secretos if secretos is not None else secretos_conocidos()):
        salida = salida.replace(valor, MARCA)
    salida = _WEBHOOK_DISCORD.sub(f"https://discord.com/api/webhooks/{MARCA}", salida)
    # La ruta del bot se tapa entera (token incluido) antes que el token suelto.
    salida = _RUTA_BOT.sub("/bot" + MARCA, salida)
    salida = _TOKEN_TELEGRAM.sub(MARCA, salida)
    return salida
