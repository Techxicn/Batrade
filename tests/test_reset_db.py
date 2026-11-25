"""reset-db: borrado manual y explícito, sólo CLI con root y sensor parado."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from batrade import cli, db, store


def _args(**kwargs):
    base = {"keep_devices": False, "keep_logs": False, "no_backup": False, "yes": True}
    base.update(kwargs)
    return SimpleNamespace(**base)


@pytest.fixture
def seeded(conn, cfg):
    """Base con inventario, eventos, puertos, escaneos, cola y solicitudes."""
    dev = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50",
                              ts=1000, hostname="laptop", fabricante="Apple")
    did = int(dev["device_id"])
    store.add_event(conn, ts=1000, tipo="device_new", severidad="warn",
                    clave_dedupe="d1", cooldown_s=0)
    store.apply_scan_ports(conn, did, [{"port": 23, "protocol": "tcp", "state": "open"}],
                           1000, cfg.scan.risky_ports)
    scan_id = store.start_scan(conn, did, "standard", "standard", "nmap", 1000)
    store.finish_scan(conn, scan_id, ts=2000, estado="ok",
                      xml_path=str(cfg.paths.scans_dir / "scan-x.xml"))
    store.create_scan_request(conn, "10.10.10.50", "quick", "test", 1000)
    store.heartbeat(conn, "sensor", 1000, "{}")
    store.record_tool_status(conn, "nmap", 1000, True)
    store.set_meta(conn, "gateway_ip", "10.10.10.1", 1000)
    for estado in ("pendiente", "enviado"):
        conn.execute(
            "INSERT INTO notification_queue(event_id, canal, intentos, proximo_intento, "
            "estado, ts) VALUES((SELECT id FROM events LIMIT 1), ?, 0, 0, ?, 1000)",
            (f"canal-{estado}", estado),
        )
    return did


def test_reset_all_empties_every_table_and_keeps_schema(conn, seeded, cfg):
    antes = store.table_counts(conn)
    assert antes["devices"] == 1 and antes["events"] == 1

    filas = store.reset_all(conn)

    assert filas["devices"] == 1 and filas["events"] == 1
    assert all(v == 0 for v in store.table_counts(conn).values())
    assert db.user_version(conn) == db.SCHEMA_VERSION
    tablas = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"devices", "events", "notification_queue", "network_baseline"} <= tablas


def test_reset_keep_devices_preserves_inventory(conn, seeded, cfg):
    store.reset_keep_devices(conn)
    counts = store.table_counts(conn)
    assert counts["devices"] == 1
    assert counts["device_history"] >= 1
    assert counts["network_baseline"] >= 1
    for vacia in ("events", "ports", "scans", "scan_requests", "notification_queue",
                  "tool_status"):
        assert counts[vacia] == 0


def test_reset_is_transactional(conn, seeded, monkeypatch):
    def boom(_conn, _tables):
        raise RuntimeError("fallo simulado")

    monkeypatch.setattr(store, "_reset_tables", boom)
    with pytest.raises(RuntimeError):
        store.reset_keep_devices(conn)
    assert store.table_counts(conn)["events"] == 1      # nada se perdió


def test_vacuum_runs_outside_transaction(conn, seeded):
    store.reset_all(conn)
    store.vacuum(conn)
    assert not conn.in_transaction


# --------------------------------------------------------------------------- #
# Guardas
# --------------------------------------------------------------------------- #
@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)


@pytest.fixture
def sensor_parado(monkeypatch):
    from batrade import daemon
    monkeypatch.setattr(daemon, "pid_of", lambda cfg, name: None)
    monkeypatch.setattr(daemon, "systemd_unit_active", lambda unit: False)


def test_requires_root(cfg, capsys, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.cmd_reset_db(cfg, _args()) == 1
    assert "sudo" in capsys.readouterr().err


def test_refuses_with_running_sensor(cfg, seeded, as_root, capsys, monkeypatch):
    from batrade import daemon
    monkeypatch.setattr(daemon, "pid_of", lambda cfg, name: 4242)
    monkeypatch.setattr(daemon, "systemd_unit_active", lambda unit: False)
    assert cli.cmd_reset_db(cfg, _args()) == 1
    assert "sensor está en ejecución" in capsys.readouterr().err
    conn = db.connect(cfg.paths.db, readonly=True)
    try:
        assert store.table_counts(conn)["events"] == 1
    finally:
        conn.close()


def test_refuses_with_active_systemd_unit(cfg, seeded, as_root, capsys, monkeypatch):
    from batrade import daemon
    monkeypatch.setattr(daemon, "pid_of", lambda cfg, name: None)
    monkeypatch.setattr(daemon, "systemd_unit_active", lambda unit: True)
    assert cli.cmd_reset_db(cfg, _args()) == 1
    assert "sensor está en ejecución" in capsys.readouterr().err


def test_aborts_without_tty_and_without_yes(cfg, seeded, as_root, sensor_parado, capsys):
    assert cli.cmd_reset_db(cfg, _args(yes=False)) == 1
    assert "sin terminal" in capsys.readouterr().err.lower()
    conn = db.connect(cfg.paths.db, readonly=True)
    try:
        assert store.table_counts(conn)["events"] == 1
    finally:
        conn.close()


def test_aborts_with_wrong_word(cfg, seeded, as_root, sensor_parado, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "vale")
    assert cli.cmd_reset_db(cfg, _args(yes=False)) == 1
    assert "cancelado" in capsys.readouterr().err


def test_accepts_typed_word(cfg, seeded, as_root, sensor_parado, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda _prompt="": cli.RESET_WORD)
    assert cli.cmd_reset_db(cfg, _args(yes=False, no_backup=True)) == 0
    assert "Base reiniciada" in capsys.readouterr().out


def test_missing_database_is_a_noop(cfg, as_root, sensor_parado, capsys):
    assert cli.cmd_reset_db(cfg, _args()) == 0
    assert "nada que reiniciar" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Copia previa
# --------------------------------------------------------------------------- #
def test_backup_is_created_with_600(cfg, seeded, as_root, sensor_parado, monkeypatch, capsys):
    monkeypatch.setattr(cli, "store_now", lambda: 1_760_000_000_000)
    assert cli.cmd_reset_db(cfg, _args()) == 0
    copia = cfg.paths.db.with_name(f"{cfg.paths.db.name}.bak-reset-1760000000000")
    assert copia.exists()
    assert copia.stat().st_mode & 0o777 == 0o600
    assert "bak-reset-1760000000000" in capsys.readouterr().out


def test_backup_is_never_overwritten(cfg, seeded, as_root, sensor_parado, monkeypatch):
    monkeypatch.setattr(cli, "store_now", lambda: 1_760_000_000_000)
    assert cli.cmd_reset_db(cfg, _args(no_backup=True)) == 0   # primero sin copia
    assert cli.cmd_reset_db(cfg, _args()) == 0
    assert cli.cmd_reset_db(cfg, _args()) == 0
    copias = sorted(p.name for p in cfg.paths.db.parent.glob("*.bak-reset-*"))
    assert copias == ["test.db.bak-reset-1760000000000",
                      "test.db.bak-reset-1760000000000-2"]


def test_no_backup_flag_skips_the_copy(cfg, seeded, as_root, sensor_parado):
    assert cli.cmd_reset_db(cfg, _args(no_backup=True)) == 0
    assert list(cfg.paths.db.parent.glob("*.bak-reset-*")) == []


def test_rotated_alerts_do_not_shadow_backup_report(cfg, seeded, as_root,
                                                    sensor_parado, monkeypatch,
                                                    capsys, caplog):
    monkeypatch.setattr(cli, "store_now", lambda: 1_760_000_000_000)
    rot1 = cfg.paths.alerts_log.with_name(cfg.paths.alerts_log.name + ".1")
    rot2 = cfg.paths.alerts_log.with_name(cfg.paths.alerts_log.name + ".2")
    rot1.write_text("vieja 1\n", encoding="utf-8")
    rot2.write_text("vieja 2\n", encoding="utf-8")

    with caplog.at_level("INFO", logger="batrade.cli"):
        assert cli.cmd_reset_db(cfg, _args()) == 0
    salida = capsys.readouterr().out
    assert not rot1.exists() and not rot2.exists()
    assert "bak-reset-1760000000000" in salida
    assert "copia         : alerts.log" not in salida
    registro = [r for r in caplog.records if r.getMessage() == "reset-db"][-1]
    assert registro.fields["backup"] == "test.db.bak-reset-1760000000000"

    # Con --no-backup tampoco puede atribuir un rotado como si fuera la copia.
    rot1.write_text("otra 1\n", encoding="utf-8")
    caplog.clear()
    with caplog.at_level("INFO", logger="batrade.cli"):
        assert cli.cmd_reset_db(cfg, _args(no_backup=True)) == 0
    salida_sin = capsys.readouterr().out
    assert not rot1.exists()
    assert "copia         :" not in salida_sin
    registro_sin = [r for r in caplog.records if r.getMessage() == "reset-db"][-1]
    assert registro_sin.fields["backup"] is None


# --------------------------------------------------------------------------- #
# Artefactos
# --------------------------------------------------------------------------- #
def _xml(cfg, nombre="scan-standard-10.10.10.50-1.xml"):
    path = cfg.paths.scans_dir / nombre
    path.write_text("<nmaprun/>", encoding="utf-8")
    return path


def test_default_scope_removes_xml_and_empties_alerts(cfg, seeded, as_root,
                                                      sensor_parado, capsys):
    xml = _xml(cfg)
    cfg.paths.alerts_log.write_text("alerta de prueba\n", encoding="utf-8")
    assert cli.cmd_reset_db(cfg, _args()) == 0
    assert not xml.exists()
    assert cfg.paths.alerts_log.read_text(encoding="utf-8") == ""
    assert cfg.paths.alerts_log.stat().st_mode & 0o777 == 0o600


def test_keep_logs_preserves_artifacts(cfg, seeded, as_root, sensor_parado):
    xml = _xml(cfg)
    cfg.paths.alerts_log.write_text("alerta de prueba\n", encoding="utf-8")
    assert cli.cmd_reset_db(cfg, _args(keep_logs=True)) == 0
    assert xml.exists()
    assert cfg.paths.alerts_log.read_text(encoding="utf-8") == "alerta de prueba\n"


def test_does_not_touch_files_outside_scans_dir(cfg, seeded, as_root, sensor_parado):
    fuera = cfg.paths.db.parent / "importante.xml"
    fuera.write_text("no se toca", encoding="utf-8")
    enlace = cfg.paths.scans_dir / "scan-trampa.xml"
    enlace.symlink_to(fuera)

    assert cli.cmd_reset_db(cfg, _args()) == 0
    assert fuera.exists()
    assert enlace.exists() or enlace.is_symlink()


def test_learning_is_active_again_after_full_reset(cfg, seeded, as_root, sensor_parado):
    previa = db.connect(cfg.paths.db)
    try:
        store.set_meta(previa, "learning_complete", "1", 1000)
        assert db.is_learning(previa) is False          # había línea base aprobada
    finally:
        previa.close()

    assert cli.cmd_reset_db(cfg, _args()) == 0

    conn = db.connect(cfg.paths.db, readonly=True)
    try:
        assert db.is_learning(conn) is True             # vuelve el aprendizaje
        assert store.get_meta(conn, "sensor_mode") is not None
    finally:
        conn.close()


def test_keep_devices_keeps_the_baseline_state(cfg, seeded, as_root, sensor_parado):
    store.set_meta(db.connect(cfg.paths.db), "learning_complete", "1", 1000)
    assert cli.cmd_reset_db(cfg, _args(keep_devices=True)) == 0
    conn = db.connect(cfg.paths.db, readonly=True)
    try:
        assert db.is_learning(conn) is False
        assert store.table_counts(conn)["devices"] == 1
    finally:
        conn.close()


def test_operation_is_logged_without_inventory_data(cfg, seeded, as_root,
                                                    sensor_parado, caplog):
    with caplog.at_level("INFO", logger="batrade.cli"):
        assert cli.cmd_reset_db(cfg, _args()) == 0
    registro = [r for r in caplog.records if r.getMessage() == "reset-db"]
    assert registro, "falta el registro de la operación"
    campos = registro[0].fields
    assert campos["alcance"] == "completo"
    assert "filas" in campos and "usuario" in campos
    assert "3c:22:fb:11:22:33" not in json.dumps(campos, default=str)
