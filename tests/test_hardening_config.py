"""Endurecimiento de configuración y de las rutas de mantenimiento (D-02, D-03, R-05)."""
from __future__ import annotations

import pytest

from batrade import db, store
from batrade.config import ConfigError, load_config
from batrade.sensor import Sensor


def _cfg(tmp_path, scan: str, sensor: str = "") -> None:
    ruta = tmp_path / "c.yaml"
    ruta.write_text(
        "network: { interface: lo, cidr: 10.10.10.0/24 }\n"
        f"scan: {scan}\n"
        + (f"sensor: {sensor}\n" if sensor else ""),
        encoding="utf-8",
    )
    return load_config(ruta, tmp_path)


# --------------------------------------------------------------------------- #
# scan: duplicados y topes
# --------------------------------------------------------------------------- #
def test_risky_ports_duplicados_son_error(tmp_path):
    scan = """{ risky_ports: [
      { port: 23, protocol: tcp, service: Telnet, reason: R },
      { port: 23, protocol: tcp, service: Telnet-alt, reason: R2 }
    ] }"""
    with pytest.raises(ConfigError) as exc:
        _cfg(tmp_path, scan)
    assert any("duplicad" in e for e in exc.value.errors)


def test_el_mismo_puerto_en_otro_protocolo_no_es_duplicado(tmp_path):
    scan = """{ risky_ports: [
      { port: 5353, protocol: tcp, service: X, reason: R },
      { port: 5353, protocol: udp, service: mDNS, reason: R }
    ] }"""
    cfg = _cfg(tmp_path, scan)
    assert (("tcp", 5353) in cfg.scan.risky_ports
            and ("udp", 5353) in cfg.scan.risky_ports)


@pytest.mark.parametrize("clave", ["standard_timeout", "quick_timeout", "udp_timeout"])
def test_los_timeouts_tienen_tope(tmp_path, clave):
    with pytest.raises(ConfigError) as exc:
        _cfg(tmp_path, f"{{ {clave}: 7200 }}")
    assert any(clave in e for e in exc.value.errors)


def test_el_tope_de_timeouts_admite_3600(tmp_path):
    cfg = _cfg(tmp_path, "{ standard_timeout: 3600, quick_timeout: 3600, udp_timeout: 3600 }")
    assert cfg.scan.standard_timeout == 3600


# --------------------------------------------------------------------------- #
# Nombres de tabla en mantenimiento
# --------------------------------------------------------------------------- #
def test_reset_rechaza_tablas_fuera_de_la_lista(conn):
    with pytest.raises(ValueError):
        store._reset_tables(conn, ("devices; DROP TABLE events",))
    with pytest.raises(ValueError):
        store._reset_tables(conn, ("sqlite_master",))


def test_table_counts_rechaza_tablas_fuera_de_la_lista(conn):
    with pytest.raises(ValueError):
        store.table_counts(conn, ("sqlite_master",))


# --------------------------------------------------------------------------- #
# Sensor.__init__ a medias
# --------------------------------------------------------------------------- #
def test_sensor_cierra_la_conexion_si_falla_a_mitad(cfg, monkeypatch):
    cerrada: dict[str, bool] = {}
    real = db.initialize

    class _Espia:
        def __init__(self, conexion):
            self._conexion = conexion

        def __getattr__(self, nombre):
            return getattr(self._conexion, nombre)

        def close(self):
            cerrada["ok"] = True
            self._conexion.close()

    monkeypatch.setattr("batrade.sensor.db.initialize",
                        lambda ruta: _Espia(real(ruta)))

    def _revienta(*_args, **_kwargs):
        raise RuntimeError("fallo al construir el motor")

    monkeypatch.setattr("batrade.sensor.Engine", _revienta)

    with pytest.raises(RuntimeError):
        Sensor(cfg, mode="degraded")
    assert cerrada.get("ok") is True
