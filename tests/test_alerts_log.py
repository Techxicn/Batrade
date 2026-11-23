"""Rotación de var/alerts.log (F-01)."""
from __future__ import annotations

import os
import stat
import time
from types import SimpleNamespace

import pytest

from batrade import cli, daemon
from batrade.notify import LocalSink
from batrade.sensor import purge_rotated_logs


def _args(**kwargs):
    base = {"keep_devices": False, "keep_logs": False, "no_backup": False, "yes": True}
    base.update(kwargs)
    return SimpleNamespace(**base)


def _modo(ruta) -> str:
    return oct(stat.S_IMODE(os.stat(ruta).st_mode))


def _sink(tmp_path, max_mb: int = 1, backups: int = 2) -> LocalSink:
    return LocalSink(tmp_path / "alerts.log", max_mb=max_mb, backups=backups)


def test_rota_por_tamano_y_conserva_los_permisos(tmp_path):
    sink = _sink(tmp_path, max_mb=1, backups=2)
    for _ in range(20):
        sink.write("x" * 200_000)          # ~1,6 MB: fuerza varias rotaciones

    base = tmp_path / "alerts.log"
    assert base.exists()
    assert _modo(base) == "0o600"
    copias = sorted(tmp_path.glob("alerts.log.*"))
    assert len(copias) == 2, [c.name for c in copias]
    for copia in copias:
        assert _modo(copia) == "0o600"


def test_sin_copias_el_log_se_trunca(tmp_path):
    sink = _sink(tmp_path, max_mb=1, backups=0)
    for _ in range(20):
        sink.write("y" * 200_000)

    assert not list(tmp_path.glob("alerts.log.*"))
    # Nunca crece por encima del tope configurado.
    assert (tmp_path / "alerts.log").stat().st_size <= 1024 * 1024


def test_un_error_de_escritura_no_tumba_al_notificador(tmp_path):
    # El "archivo" es un directorio: abrirlo en modo append da OSError.
    objetivo = tmp_path / "alerts.log"
    objetivo.mkdir()
    sink = LocalSink(objetivo, max_mb=1, backups=1)

    sink.write("no debe lanzar")   # no lanza: se registra en el log


def test_la_retencion_borra_las_copias_viejas(tmp_path):
    base = tmp_path / "alerts.log"
    base.write_text("actual\n", encoding="utf-8")
    vieja = tmp_path / "alerts.log.1"
    vieja.write_text("vieja\n", encoding="utf-8")
    nueva = tmp_path / "alerts.log.2"
    nueva.write_text("nueva\n", encoding="utf-8")

    antiguo = time.time() - 40 * 86400
    os.utime(vieja, (antiguo, antiguo))

    borradas = purge_rotated_logs(base, cutoff_ts=int(time.time() * 1000) - 30 * 86400_000)

    assert borradas == 1
    assert not vieja.exists()
    assert nueva.exists() and base.exists()


def test_la_retencion_no_toca_archivos_ajenos(tmp_path):
    base = tmp_path / "alerts.log"
    base.write_text("actual\n", encoding="utf-8")
    ajeno = tmp_path / "otro.log.1"
    ajeno.write_text("x\n", encoding="utf-8")
    antiguo = time.time() - 40 * 86400
    os.utime(ajeno, (antiguo, antiguo))

    assert purge_rotated_logs(base, cutoff_ts=int(time.time() * 1000)) == 0
    assert ajeno.exists()


# --------------------------------------------------------------------------- #
# reset-db
# --------------------------------------------------------------------------- #
@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(daemon, "pid_of", lambda cfg, name: None)
    monkeypatch.setattr(daemon, "systemd_unit_active", lambda unit: False)


def test_reset_db_borra_tambien_las_copias(cfg, as_root, capsys):
    from batrade import db

    db.initialize(cfg.paths.db).close()
    cfg.paths.alerts_log.parent.mkdir(parents=True, exist_ok=True)
    cfg.paths.alerts_log.write_text("actual\n", encoding="utf-8")
    copia = cfg.paths.alerts_log.with_name("alerts.log.1")
    copia.write_text("vieja\n", encoding="utf-8")

    assert cli.cmd_reset_db(cfg, _args()) == 0
    assert cfg.paths.alerts_log.exists()
    assert cfg.paths.alerts_log.read_text(encoding="utf-8") == ""   # vaciado
    assert not copia.exists()
