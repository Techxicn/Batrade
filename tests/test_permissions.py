"""Permisos de archivos: .env y los logs del sensor (S-06, S-07)."""
from __future__ import annotations

import os
import stat

from batrade import cli, db
from batrade.logging_setup import setup_logging


def _modo(ruta) -> str:
    return oct(stat.S_IMODE(os.stat(ruta).st_mode))


# --------------------------------------------------------------------------- #
# .env legible por otros
# --------------------------------------------------------------------------- #
def test_doctor_avisa_si_el_env_es_legible_por_otros(cfg, capsys):
    env = cfg.root / ".env"
    env.write_text("TELEGRAM_TOKEN=x\n", encoding="utf-8")
    env.chmod(0o644)
    db.initialize(cfg.paths.db)

    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out
    assert "chmod 600 .env" in salida
    assert ".env" in salida


def test_doctor_no_avisa_con_env_600(cfg, capsys):
    env = cfg.root / ".env"
    env.write_text("TELEGRAM_TOKEN=x\n", encoding="utf-8")
    env.chmod(0o600)
    db.initialize(cfg.paths.db)

    cli.cmd_doctor(cfg, None)
    assert "chmod 600 .env" not in capsys.readouterr().out


def test_init_avisa_si_el_env_es_legible_por_otros(cfg, capsys):
    env = cfg.root / ".env"
    env.write_text("TELEGRAM_TOKEN=x\n", encoding="utf-8")
    env.chmod(0o640)

    cli.cmd_init(cfg, None)
    assert "chmod 600 .env" in capsys.readouterr().out


def test_sin_env_no_hay_aviso(cfg, capsys):
    db.initialize(cfg.paths.db)
    cli.cmd_doctor(cfg, None)
    assert "chmod 600 .env" not in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Logs del sensor
# --------------------------------------------------------------------------- #
def test_el_log_nace_600_y_el_directorio_700(tmp_path):
    log_dir = tmp_path / "log"
    logger = setup_logging(log_dir, component="permisos-prueba", console=False)
    logger.info("hola")
    for handler in logger.handlers:
        handler.flush()

    assert _modo(log_dir) == "0o700"
    assert _modo(log_dir / "permisos-prueba.log") == "0o600"


def test_la_rotacion_conserva_600(tmp_path):
    log_dir = tmp_path / "log"
    logger = setup_logging(log_dir, component="permisos-rotacion", console=False)
    handler = next(h for h in logger.handlers
                   if hasattr(h, "doRollover"))
    handler.maxBytes = 200
    for _ in range(40):
        logger.info("x" * 60)
    handler.flush()

    archivos = sorted(log_dir.glob("permisos-rotacion.log*"))
    assert len(archivos) > 1, "no rotó: la prueba no sirve"
    for archivo in archivos:
        assert _modo(archivo) == "0o600", archivo
