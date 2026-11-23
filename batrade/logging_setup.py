"""Logging estructurado con rotación (RNF-07).

Un archivo JSONL para máquina y consola legible para humano. Los errores de
herramientas externas deben registrarse con el comando y el código de salida.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from batrade.redact import redactar, secretos_conocidos

_LOGGERS: dict[str, logging.Logger] = {}


class RedactingFilter(logging.Filter):
    """Tapa tokens y webhooks en el mensaje, los argumentos y los campos.

    Se instala en cada handler, no en el logger: así también cubre los registros
    que emiten librerías y los que llegan con `exc_info`.
    """

    def __init__(self, secretos: tuple[str, ...] | None = None) -> None:
        super().__init__()
        self._secretos = secretos

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redactar(record.msg, self._secretos)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (redactar(v, self._secretos)
                                   if isinstance(v, str) else v)
                               for k, v in record.args.items()}
            else:
                record.args = tuple(redactar(a, self._secretos)
                                    if isinstance(a, str) else a
                                    for a in record.args)
        campos = getattr(record, "fields", None)
        if isinstance(campos, dict):
            record.fields = {
                k: (redactar(v, self._secretos) if isinstance(v, str) else v)
                for k, v in campos.items()
            }
        if record.exc_info is not None:
            # El traceback también puede arrastrar la URL con el token.
            record.exc_text = redactar(
                logging.Formatter().formatException(record.exc_info), self._secretos)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redactar(record.exc_text, self._secretos)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        elif record.exc_text:
            payload["exc"] = record.exc_text
        return json.dumps(payload, ensure_ascii=False, default=str)


class HumanFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        fields = getattr(record, "fields", None)
        tail = ""
        if isinstance(fields, dict) and fields:
            tail = " " + " ".join(f"{k}={v}" for k, v in fields.items())
        return f"{ts} {record.levelname:<7} {record.name:<18} {record.getMessage()}{tail}"


class _RotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotación que crea el archivo con 600, también tras cada rollover.

    `RotatingFileHandler` usa el umask del proceso (normalmente 022), así que un
    log con nombres de equipos nacía legible por todo el sistema.
    """

    def _open(self):  # noqa: ANN202 - firma de la clase base
        flujo = super()._open()
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            pass
        return flujo


def setup_logging(log_dir: Path, component: str = "batrade", level: int = logging.INFO,
                  console: bool = True) -> logging.Logger:
    """Configura (idempotente) el logger del componente."""
    if component in _LOGGERS:
        return _LOGGERS[component]

    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(log_dir, 0o700)  # sólo el usuario del sensor
    except OSError:
        pass
    logger = logging.getLogger(component)
    logger.setLevel(level)
    logger.propagate = False

    fh = _RotatingFileHandler(
        log_dir / f"{component}.log", maxBytes=2 * 1024 * 1024, backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(JsonFormatter())
    fh.addFilter(RedactingFilter(secretos_conocidos()))
    logger.addHandler(fh)

    if console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(HumanFormatter())
        ch.addFilter(RedactingFilter(secretos_conocidos()))
        logger.addHandler(ch)

    _LOGGERS[component] = logger
    return logger


def log(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    """Log con campos estructurados, seguros ante claves reservadas de logging."""
    logger.log(level, msg, extra={"fields": fields})
