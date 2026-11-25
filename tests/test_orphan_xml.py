"""Huérfanos de XML: barrido de la retención (F-05)."""
from __future__ import annotations

import os
import time

from batrade import store
from batrade.sensor import purge_orphan_xml


def _viejo(ruta, horas: int = 25) -> None:
    marca = time.time() - horas * 3600
    os.utime(ruta, (marca, marca))


def test_borra_solo_los_huerfanos_viejos(conn, cfg):
    escaneos = cfg.paths.scans_dir
    escaneos.mkdir(parents=True, exist_ok=True)

    huerfano = escaneos / "scan-quick-huerfano.xml"
    huerfano.write_text("<nmaprun/>", encoding="utf-8")
    _viejo(huerfano)

    referenciado = escaneos / "scan-standard-ok.xml"
    referenciado.write_text("<nmaprun/>", encoding="utf-8")
    _viejo(referenciado)

    reciente = escaneos / "scan-quick-reciente.xml"
    reciente.write_text("<nmaprun/>", encoding="utf-8")

    dev = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50", ts=1000)
    scan_id = store.start_scan(conn, int(dev["device_id"]), "standard", "standard",
                               "nmap", 1000)
    store.finish_scan(conn, scan_id, ts=2000, estado="ok",
                      xml_path=str(referenciado))

    borrados = purge_orphan_xml(conn, escaneos, int(time.time() * 1000), max_age_ms=24 * 3600_000)

    assert borrados == 1
    assert not huerfano.exists()
    assert referenciado.exists()
    assert reciente.exists()


def test_no_sigue_symlinks_ni_sale_del_directorio(conn, cfg, tmp_path):
    escaneos = cfg.paths.scans_dir
    escaneos.mkdir(parents=True, exist_ok=True)
    fuera = tmp_path / "importante.xml"
    fuera.write_text("<nmaprun/>", encoding="utf-8")
    _viejo(fuera)

    enlace = escaneos / "scan-trampa.xml"
    enlace.symlink_to(fuera)

    borrados = purge_orphan_xml(conn, escaneos, int(time.time() * 1000))

    assert borrados == 0
    assert fuera.exists()
    assert enlace.is_symlink()


def test_sin_directorio_de_escaneos_no_falla(conn, cfg):
    assert purge_orphan_xml(conn, cfg.paths.scans_dir, int(time.time() * 1000)) == 0


def test_un_xml_de_intento_fallido_viejo_se_limpia(conn, cfg):
    """El de un fallo reciente ya lo borra run_scan; si quedó uno viejo, cae aquí."""
    escaneos = cfg.paths.scans_dir
    escaneos.mkdir(parents=True, exist_ok=True)
    resto = escaneos / "scan-standard-10.10.10.50-123.xml"
    resto.write_text("<?xml version='1.0'?><nmaprun>", encoding="utf-8")
    _viejo(resto, horas=48)

    assert purge_orphan_xml(conn, escaneos, int(time.time() * 1000)) == 1
    assert not resto.exists()
