"""Redacción de secretos en textos que se registran o se guardan (S-01, S-02).

Una excepción HTTP (``urllib``) puede arrastrar la URL completa: ``/bot<token>/`` en
Telegram y ``/api/webhooks/<id>/<token>`` en Discord. Aquí se tapan esos
patrones y, además, los valores exactos de las variables de canal configuradas,
antes de que el texto llegue al log, a ``notification_queue.last_error``, a
``/health`` o a ``var/alerts.log``.
"""
from __future__ import annotations

from collections.abc import Mapping
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

# Variables de entorno que pueden llevar secretos de canal o de acceso al panel.
VARIABLES_DE_CANAL = ("TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "DISCORD_WEBHOOK",
                      "DASHBOARD_TOKEN")


def secretos_conocidos(extra: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Valores no vacíos de las variables sensibles del proceso y de ``extra``."""
    fuente: dict[str, str] = {**dict(extra or {}), **os.environ}
    valores = [fuente.get(nombre, "") for nombre in VARIABLES_DE_CANAL]
    if extra:
        valores.extend(extra.values())
    vistos: dict[str, None] = {}
    for valor in valores:
        if len(valor) >= 8:
            vistos[valor] = None
    return tuple(vistos)


def redactar(texto: object, secretos: tuple[str, ...] | None = None) -> str:
    """Devuelve ``texto`` sin tokens de Telegram, webhooks de Discord ni secretos.

    ``secretos`` permite fijar la lista (útil en tests y en el filtro de
    logging, que la calcula una vez); si es ``None`` se leen del entorno.
    """
    salida = str(texto)
    # Primero las URLs completas: si se sustituye antes un token por `<redactado>`,
    # los signos `<`/`>` cortan el patrón `/bot...` y dejan expuesta la ruta.
    salida = _WEBHOOK_DISCORD.sub(f"https://discord.com/api/webhooks/{MARCA}", salida)
    salida = _RUTA_BOT.sub("/bot" + MARCA, salida)
    for valor in (secretos if secretos is not None else secretos_conocidos()):
        salida = salida.replace(valor, MARCA)
    salida = _TOKEN_TELEGRAM.sub(MARCA, salida)
    return salida
